"""Cross-adapter portability: export on one storage adapter, reload on a DIFFERENT one.

A round trip through a single adapter proves less than it looks like it proves. The same
implementation writes and reads, so a field the writer quietly drops is a field the reader
never misses, and the trail agrees with itself all the way to the assertion. The claim an
institution actually needs is that its evidence leaves one store and lands whole in another,
so this module runs every proof across two genuinely different storage implementations:

* ``sqlite``: :class:`hex_service_kit.audit.HashChainedAuditLog`, an append-only SQLite table
  with UPDATE/DELETE triggers.
* ``jsonl``: :class:`hex_service_kit.audit.JsonlFileAuditLog`, a plain append-only JSON Lines
  file with no database engine, no triggers and no SQL, whose on-disk record shape is not the
  export's record shape.

:func:`_prove_portable` is the proof, and it is deliberately strict: the destination must
import the file, verify its chain, adopt the witness that travelled rather than mint one,
end on the head the SOURCE witnessed OUT OF BAND, re-export byte for byte, and hand back
every field of every record, including the fields a lossy hop would silently default.

A green check is only evidence if it was first observed red, so the falsification cases below
matter more than the happy path: each one corrupts the handover exactly the way a real
migration goes wrong, then asserts the proof FAILS. They cover the defect class this repo has
already been bitten by once, where a five-record export truncated to three imported clean and
reported "chain intact", plus its mutated-record and forged-witness siblings.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import pytest

from hex_service_kit.audit import (
    EXPORT_FORMAT,
    AuditChainError,
    AuditStorePort,
    HashChainedAuditLog,
    JsonlFileAuditLog,
)
from hex_service_kit.serialization import dataclass_from_jsonable, to_jsonable

# --------------------------------------------------------------------------- #
# A synthetic evidence record with the field kinds a regulated trail really carries
# --------------------------------------------------------------------------- #


class Decision(StrEnum):
    ESCALATED = "escalated"
    APPROVED = "approved"


class ReviewState(StrEnum):
    AWAITING_CHECKER = "awaiting_checker"
    SIGNED_OFF = "signed_off"


@dataclass(frozen=True, slots=True)
class Citation:
    source_id: str
    page: int | None
    snippet: str
    score: float | None


@dataclass(frozen=True, slots=True)
class SignOff:
    """Maker-checker: who reviewed, who approved, when, against which version."""

    maker: str
    checker: str
    approved_at: datetime
    against_version: str


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    action: str
    actor: str
    decision: Decision
    review_state: ReviewState
    redacted_prompt: str
    # Beyond 2**53: a hop that ever routes a figure through a float loses this exactly.
    exposure_minor_units: int
    confidence: float
    breaching: bool
    citations: tuple[Citation, ...]
    sign_off: SignOff | None
    routing_history: tuple[str, ...]
    regulatory_clock_days: int | None
    metadata: dict[str, str]
    recorded_at: datetime


def _evidence(i: int) -> EvidenceRecord:
    """One synthetic record. Obviously fictional identifiers, deliberately awkward values."""
    return EvidenceRecord(
        action="assess",
        actor="analyst@bank.example",
        decision=Decision.ESCALATED if i % 2 else Decision.APPROVED,
        review_state=ReviewState.AWAITING_CHECKER,
        redacted_prompt=f"[PERSON_NAME] requested dossier {i}, réf. ДОСЬЕ",
        exposure_minor_units=9_007_199_254_740_993 + i,
        confidence=0.1 + 0.2,
        breaching=bool(i % 2),
        citations=(
            Citation(source_id=f"doc-{i}", page=None, snippet="", score=None),
            Citation(source_id="policy-7", page=12, snippet="clause 4.2§b", score=0.5),
        ),
        sign_off=(
            None
            if i == 0
            else SignOff(
                maker="maker@bank.example",
                checker="checker@bank.example",
                approved_at=datetime(2026, 3, 4, 5, 6, 7, 891011, tzinfo=UTC),
                against_version="policy/2026.02",
            )
        ),
        routing_history=("intake", "first-line", "second-line"),
        regulatory_clock_days=None if i == 0 else 30 - i,
        metadata={
            "case/ref": f"CASE-{i:04d}",
            "note": "line one\nline two\twith a tab",
            "empty": "",
        },
        recorded_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC) + timedelta(seconds=i),
    )


# --------------------------------------------------------------------------- #
# The two adapters, and the handover between them
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Party:
    """One side of the migration: an evidence store plus the anchor file witnessing it."""

    kind: str
    store: AuditStorePort
    anchor: Path
    data: Path


def _sqlite_party(tmp_path: Path, name: str) -> Party:
    data, anchor = tmp_path / f"{name}.db", tmp_path / f"{name}.anchor"
    return Party("sqlite", HashChainedAuditLog(str(data), anchor_path=str(anchor)), anchor, data)


def _jsonl_party(tmp_path: Path, name: str) -> Party:
    data, anchor = tmp_path / f"{name}.jsonl", tmp_path / f"{name}.anchor"
    return Party("jsonl", JsonlFileAuditLog(data, anchor_path=str(anchor)), anchor, data)


ADAPTERS: dict[str, Callable[[Path, str], Party]] = {
    "sqlite": _sqlite_party,
    "jsonl": _jsonl_party,
}
# The pairs that carry the claim: the export and the reload run on different implementations.
CROSS_PAIRS = [("sqlite", "jsonl"), ("jsonl", "sqlite")]
# The same-adapter controls run too, so "it passed" cannot mean "it only ever passed at home".
ALL_PAIRS = [*CROSS_PAIRS, ("sqlite", "sqlite"), ("jsonl", "jsonl")]
PAIR_IDS = [f"{source}-to-{target}" for source, target in ALL_PAIRS]
CROSS_IDS = [f"{source}-to-{target}" for source, target in CROSS_PAIRS]


@dataclass(frozen=True)
class Handover:
    """What leaves the source: the export file, and the head witnessed on a second channel."""

    export: Path
    records: int
    #: Read from the SOURCE's own anchor file, which travels separately from the data. An
    #: actor who rewrites the export file cannot reach this, which is the entire reason a
    #: fully re-chained forgery is catchable at all.
    witnessed_head: str


def _seed(party: Party, count: int) -> list[EvidenceRecord]:
    records = [_evidence(i) for i in range(count)]
    for record in records:
        party.store.record(record)
    return records


def _hand_over(source: Party, tmp_path: Path) -> Handover:
    export = tmp_path / f"handover-from-{source.kind}.jsonl"
    written = source.store.export_jsonl(export)
    witness = json.loads(source.anchor.read_text(encoding="utf-8"))
    return Handover(export=export, records=written, witnessed_head=str(witness["entry_hash"]))


def _header(export: Path) -> dict[str, object]:
    return dict(json.loads(export.read_text(encoding="utf-8").splitlines()[0]))


def _prove_portable(
    target: Party,
    handover: Handover,
    expected: Sequence[EvidenceRecord],
    tmp_path: Path,
) -> None:
    """The portability proof, run at the DESTINATION. Raises if anything failed to survive.

    Every falsification test below calls exactly this, so the corruptions are measured against
    the same bar the happy path clears rather than against a weaker restatement of it.

    Ordered so the checks an institution can really perform come first. Comparing the arrived
    records against the originals is a luxury of a test that holds both sides; a migration
    holds only what the source witnessed out of band, so the head check has to be able to
    stand on its own, and is asserted before anything that peeks at the source.
    """
    imported = target.store.import_jsonl(handover.export)
    assert imported == handover.records, "the destination restored a different number of records"

    report = target.store.verify_chain()
    assert report.ok, f"the destination refused to call the restored trail intact: {report.detail}"
    assert report.entries == len(expected)
    assert report.chained == len(expected)
    assert report.legacy == 0

    # The witness was ADOPTED from the export, never minted here from the payload that
    # arrived: an anchor derived from a truncated trail witnesses only the truncation.
    assert target.anchor.exists(), "the destination adopted no witness at all"
    header = _header(handover.export)
    assert "anchor" in header, "the export arrived with no anchor header, so nothing witnesses it"
    adopted = json.loads(target.anchor.read_text(encoding="utf-8"))
    assert adopted == header["anchor"], "the destination's witness is not the one that travelled"

    # Re-export, which is both the destination's own statement of where its trail ends and
    # the strictest fidelity check available: seq numbering, both hashes, the anchor header
    # and the exact canonical JSON of every event, all reproduced from the destination alone.
    onward = tmp_path / f"onward-from-{target.kind}.jsonl"
    assert target.store.export_jsonl(onward) == handover.records

    # The head the SOURCE witnessed out of band, which no rewrite of the export can reach.
    onward_anchor = _header(onward)["anchor"]
    assert isinstance(onward_anchor, dict)
    assert onward_anchor["entry_hash"] == handover.witnessed_head, (
        "the destination ended on a different head than the source witnessed out of band"
    )
    assert onward_anchor["seq"] == len(expected)

    assert onward.read_text(encoding="utf-8") == handover.export.read_text(encoding="utf-8"), (
        "the destination re-exports different bytes than it received"
    )

    restored = target.store.read_all()
    assert len(restored) == len(expected)
    for original, payload in zip(expected, restored, strict=True):
        source_payload = to_jsonable(original)
        assert set(payload) == set(source_payload), (
            "the destination is missing (or invented) top-level fields"
        )
        for field in fields(original):
            assert payload[field.name] == source_payload[field.name], (
                f"field {field.name!r} did not survive the move to {target.kind}"
            )
        assert dataclass_from_jsonable(EvidenceRecord, payload) == original


# --------------------------------------------------------------------------- #
# The two adapters really are two adapters
# --------------------------------------------------------------------------- #


def test_both_adapters_satisfy_the_audit_store_port(tmp_path: Path) -> None:
    """The port is what makes "a different adapter" mean something checkable."""
    assert isinstance(HashChainedAuditLog(), AuditStorePort)
    assert isinstance(JsonlFileAuditLog(tmp_path / "trail.jsonl"), AuditStorePort)


def test_the_two_stores_are_genuinely_different_storage(tmp_path: Path) -> None:
    """Asserted, not asserted-in-prose: one is a SQLite database, one is a text file.

    The cross-adapter proof is only worth running if the two sides are not the same store
    wearing two names, so the difference is pinned here rather than left to a class name.
    """
    sqlite_party, jsonl_party = _sqlite_party(tmp_path, "a"), _jsonl_party(tmp_path, "b")
    _seed(sqlite_party, 2)
    _seed(jsonl_party, 2)

    assert sqlite_party.data.read_bytes().startswith(b"SQLite format 3")

    lines = jsonl_party.data.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        row = json.loads(line)
        # The store's own shape: the exact hashed string, and no seq (the line position is
        # the seq). Not the export's shape, so a round trip has to convert, not copy.
        assert set(row) == {"prev_hash", "entry_hash", "event_json"}
        assert isinstance(row["event_json"], str)


def test_the_audit_module_pulls_in_no_web_or_cloud_client() -> None:
    """Core purity, checked in a clean interpreter rather than inside the test session.

    The kit's core is stdlib-only on purpose, and the way that gets lost is a convenience
    import in one module dragging a client library into every consumer's decision core. The
    check runs in a subprocess because pytest itself has already imported a web stack here.
    """
    probe = (
        "import sys; import hex_service_kit.audit;"
        "leaked = sorted(m for m in sys.modules if m.split('.')[0] in "
        "{'httpx', 'requests', 'fastapi', 'starlette', 'google', 'opentelemetry', 'urllib3'});"
        "print(','.join(leaked))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"audit.py leaked into the core: {result.stdout.strip()}"


# --------------------------------------------------------------------------- #
# The proof: full-fidelity round trip across adapters
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("source_kind", "target_kind"), ALL_PAIRS, ids=PAIR_IDS)
def test_the_evidence_set_survives_the_move_field_for_field(
    tmp_path: Path, source_kind: str, target_kind: str
) -> None:
    """Export on adapter A, reload on adapter B, and account for every field.

    The cross pairs are the claim; the same-adapter pairs run alongside them so a failure
    can be attributed to the move rather than to the store.
    """
    source = ADAPTERS[source_kind](tmp_path, "source")
    records = _seed(source, 5)
    handover = _hand_over(source, tmp_path)
    assert handover.records == 5

    target = ADAPTERS[target_kind](tmp_path, "target")
    _prove_portable(target, handover, records, tmp_path)

    # And the destination is a working store, not a read-only landing pad.
    target.store.record(_evidence(99))
    assert target.store.verify_chain().ok


@pytest.mark.parametrize(("source_kind", "target_kind"), CROSS_PAIRS, ids=CROSS_IDS)
def test_a_trail_stays_verifiable_across_three_hops(
    tmp_path: Path, source_kind: str, target_kind: str
) -> None:
    """A migration is rarely one hop. A to B to A must not degrade anything on the way."""
    source = ADAPTERS[source_kind](tmp_path, "source")
    records = _seed(source, 4)

    middle = ADAPTERS[target_kind](tmp_path, "middle")
    _prove_portable(middle, _hand_over(source, tmp_path), records, tmp_path)

    hop2 = tmp_path / "hop2"
    hop2.mkdir()
    back = ADAPTERS[source_kind](hop2, "back")
    _prove_portable(back, _hand_over(middle, hop2), records, hop2)


# --------------------------------------------------------------------------- #
# Falsification: the proof has to be able to FAIL, or it is not evidence
# --------------------------------------------------------------------------- #


def _record_lines(export: Path) -> list[str]:
    return [line for line in export.read_text(encoding="utf-8").splitlines() if line.strip()][1:]


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _forge_whole_export(
    export: Path, doctor: Callable[[dict[str, object]], dict[str, object]]
) -> None:
    """Rewrite an entire export, re-chaining every hash and re-anchoring the header.

    Deliberately written with nothing but ``hashlib`` and ``json``, importing no private
    helper from the kit, because that is exactly the position the forger is in: the chain
    carries no secret, so an actor holding the file can hand over a wholly self-consistent
    trail. Anything this file says about itself is therefore worthless on its own.
    """
    prev, lines = "", []
    for seq, line in enumerate(_record_lines(export), start=1):
        event = doctor(dict(json.loads(line)["event"]))
        event_json = _canonical_json(event)
        digest = hashlib.sha256(
            prev.encode("utf-8") + b"\n" + event_json.encode("utf-8")
        ).hexdigest()
        lines.append(
            _canonical_json({"seq": seq, "prev_hash": prev, "entry_hash": digest, "event": event})
        )
        prev = digest
    header = _canonical_json(
        {"anchor": {"seq": len(lines), "entry_hash": prev}, "format": EXPORT_FORMAT}
    )
    export.write_text("\n".join([header, *lines]) + "\n", encoding="utf-8")


@pytest.mark.parametrize(("source_kind", "target_kind"), CROSS_PAIRS, ids=CROSS_IDS)
def test_a_truncated_history_is_refused_by_the_destination_adapter(
    tmp_path: Path, source_kind: str, target_kind: str
) -> None:
    """Falsification 1, the defect this repo has already been bitten by once.

    Five records are exported and the newest two are deleted in transit. The surviving chain
    links perfectly, so nothing inside the shortened file objects: only the anchor header that
    travelled with it says which record the trail was supposed to end on.

    Observed RED with the anchor-vs-head check deleted from ``_restore_lines``, in both
    directions: ``AssertionError: the destination restored a different number of records /
    assert 3 == 5``. The shortened export was accepted at the door, three records landing
    where five were sent, which is precisely the shape of the defect this repo has already
    shipped once.
    """
    source = ADAPTERS[source_kind](tmp_path, "source")
    records = _seed(source, 5)
    handover = _hand_over(source, tmp_path)
    lines = handover.export.read_text(encoding="utf-8").splitlines()
    handover.export.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")

    target = ADAPTERS[target_kind](tmp_path, "target")
    with pytest.raises(AuditChainError, match="missing from the tail"):
        _prove_portable(target, handover, records, tmp_path)

    # Refusing means nothing lands: no shortened trail to read back, re-export or witness.
    assert target.store.read_all() == []
    assert target.store.verify_chain().entries == 0
    assert not target.anchor.exists()


@pytest.mark.parametrize(("source_kind", "target_kind"), CROSS_PAIRS, ids=CROSS_IDS)
def test_a_mutated_record_is_refused_by_the_destination_adapter(
    tmp_path: Path, source_kind: str, target_kind: str
) -> None:
    """Falsification 2: one field of one record is edited somewhere along the way.

    Observed RED with the import-time ``entry_hash`` re-derivation deleted from
    ``_restore_lines``, in both directions: ``AssertionError: the destination refused to call
    the restored trail intact: seq 4: entry_hash mismatch (record altered in place)``, over
    ``ChainReport(ok=False, entries=5, chained=3, legacy=0, first_bad_seq=4)``. All five
    records had landed, doctored one included, so a tamper that should have been refused at
    the door was instead written into the destination's WORM store and left for the next
    verify to find. Catching it twice is the point; catching it only the second time is not
    the same guarantee.
    """
    source = ADAPTERS[source_kind](tmp_path, "source")
    records = _seed(source, 5)
    handover = _hand_over(source, tmp_path)
    doctored = handover.export.read_text(encoding="utf-8").replace("dossier 3", "DOCTORED")
    assert "DOCTORED" in doctored
    handover.export.write_text(doctored, encoding="utf-8")

    target = ADAPTERS[target_kind](tmp_path, "target")
    with pytest.raises(AuditChainError, match="altered in transit"):
        _prove_portable(target, handover, records, tmp_path)

    assert target.store.read_all() == []
    assert not target.anchor.exists()


@pytest.mark.parametrize(("source_kind", "target_kind"), CROSS_PAIRS, ids=CROSS_IDS)
def test_an_export_that_arrives_without_its_anchor_never_verifies_at_the_destination(
    tmp_path: Path, source_kind: str, target_kind: str
) -> None:
    """Falsification 3a: the witness does not travel, so the destination cannot claim intact.

    The records are untouched and the chain is perfect, which is exactly the trap: with no
    head to end on, a whole trail and a trail with its newest records dropped are the same
    file. The destination has to load it and say so, not verify it.

    Observed RED with ``import_jsonl`` minting an anchor from the payload it was handed
    (``self._unanchored_restore = False`` plus ``self._write_anchor()`` in place of adopting
    the travelled anchor), in both directions: ``AssertionError: the destination called a
    trail whose witness never arrived intact``. The laundering is one line of plausible
    convenience, and it turns "nothing witnesses this" into a clean verify and a witness file
    that agrees with whatever was just received.
    """
    source = ADAPTERS[source_kind](tmp_path, "source")
    records = _seed(source, 5)
    handover = _hand_over(source, tmp_path)
    handover.export.write_text("\n".join(_record_lines(handover.export)) + "\n", encoding="utf-8")

    # It loads: an unanchored export is still a valid chain, and refusing it would lose data
    # that a pre-anchor system legitimately wrote. What it can never be is "verified".
    target = ADAPTERS[target_kind](tmp_path, "target")
    assert target.store.import_jsonl(handover.export) == 5
    report = target.store.verify_chain()
    assert not report.ok, "the destination called a trail whose witness never arrived intact"
    assert "no chain anchor" in report.detail
    assert len(target.store.read_all()) == 5
    assert not target.anchor.exists(), "the destination minted a witness from the payload it got"

    # And the proof as a whole refuses it, on a destination that has seen nothing else.
    second = ADAPTERS[target_kind](tmp_path, "second")
    with pytest.raises(AssertionError, match="refused to call the restored trail intact"):
        _prove_portable(second, handover, records, tmp_path)


@pytest.mark.parametrize(("source_kind", "target_kind"), CROSS_PAIRS, ids=CROSS_IDS)
def test_a_forged_anchor_is_caught_only_by_the_head_that_travelled_out_of_band(
    tmp_path: Path, source_kind: str, target_kind: str
) -> None:
    """Falsification 3b: every record rewritten, every hash re-derived, the header re-anchored.

    The hardest case and the honest one. A decision recorded as escalated is rewritten as
    approved and signed off, the whole chain is recomputed around it, and the anchor header
    is minted to match. The file is internally perfect, the record count is unchanged, and
    nothing the destination can read objects to any of it. The only thing that disagrees is
    the head the source witnessed on a channel the forger never had, which is why the export
    is not the whole handover and the anchor has to travel separately from the data.

    Observed RED with the two checks a real migration cannot perform deleted from
    ``_prove_portable`` (the out-of-band head comparison, and the field-by-field compare
    against records only a test still holds), in both directions: ``Failed: DID NOT RAISE
    AssertionError``. The forgery cleared everything the destination can see, byte-for-byte
    re-export included, and left five records saying the opposite of what happened.
    """
    source = ADAPTERS[source_kind](tmp_path, "source")
    records = _seed(source, 5)
    handover = _hand_over(source, tmp_path)
    _forge_whole_export(
        handover.export,
        lambda event: {**event, "decision": "approved", "review_state": "signed_off"},
    )

    target = ADAPTERS[target_kind](tmp_path, "target")
    with pytest.raises(AssertionError, match="out of band"):
        _prove_portable(target, handover, records, tmp_path)

    # The limit, stated rather than implied: nothing inside the file objected to any of it.
    assert target.store.verify_chain().ok
    assert len(target.store.read_all()) == 5
    assert {str(event["decision"]) for event in target.store.read_all()} == {"approved"}


def test_an_unreadable_destination_store_is_reported_rather_than_raised(tmp_path: Path) -> None:
    """A file store can be corrupted in ways a table cannot, and verify still owes an answer.

    Garbling a line of the JSONL store is not a chain break the walk can describe, so this is
    the one place the file adapter needs its own answer: a report saying the store cannot be
    read, not a ``ValueError`` thrown past the verifier that asked.
    """
    party = _jsonl_party(tmp_path, "store")
    _seed(party, 3)
    lines = party.data.read_text(encoding="utf-8").splitlines()
    party.data.write_text("\n".join([lines[0], "{not json", *lines[1:]]) + "\n", encoding="utf-8")

    report = party.store.verify_chain()
    assert not report.ok
    assert "not readable JSON" in report.detail
    assert report.entries == 4
