"""Tamper-evident audit chain + open-format round-trip.

Every entry is cryptographically chained to its predecessor, stored/exported in a plain
documented format (JSON Lines), and a full export reloads on a fresh store with every field
and the chain intact.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import pytest

from hex_service_kit.audit import EXPORT_FORMAT, AuditChainError, HashChainedAuditLog


class Decision(StrEnum):
    ESCALATED = "escalated"


@dataclass(frozen=True, slots=True)
class Event:
    action: str
    actor: str
    decision: Decision
    redacted_prompt: str
    when: datetime = field(default_factory=lambda: datetime(2026, 1, 1, tzinfo=UTC))


def _event(i: int) -> Event:
    return Event(
        action="assess",
        actor="analyst@bank.test",
        decision=Decision.ESCALATED,
        redacted_prompt=f"[PERSON_NAME] asked for dossier {i}",
    )


def test_chain_intact_after_records():
    audit = HashChainedAuditLog()
    for i in range(5):
        audit.record(_event(i))
    report = audit.verify_chain()
    assert report.ok, report.detail
    assert report.entries == 5
    assert report.chained == 5
    assert report.legacy == 0


def test_plain_dict_events_are_accepted():
    audit = HashChainedAuditLog()
    audit.record({"action": "a", "n": 1})
    assert audit.read_all() == [{"action": "a", "n": 1}]


def test_non_object_event_is_rejected():
    audit = HashChainedAuditLog()
    with pytest.raises(TypeError, match="JSON object"):
        audit.record(["not", "an", "object"])


def test_in_place_tamper_is_detected():
    audit = HashChainedAuditLog()
    for i in range(3):
        audit.record(_event(i))
    audit._conn.execute("DROP TRIGGER audit_log_no_update")
    audit._conn.execute(
        "UPDATE audit_log SET event_json = replace(event_json, 'dossier 1', 'DOCTORED') "
        "WHERE seq = 2"
    )
    audit._conn.commit()
    report = audit.verify_chain()
    assert not report.ok
    assert report.first_bad_seq == 2
    assert "altered" in report.detail


def test_deleting_a_record_breaks_the_chain():
    audit = HashChainedAuditLog()
    for i in range(3):
        audit.record(_event(i))
    audit._conn.execute("DROP TRIGGER audit_log_no_delete")
    audit._conn.execute("DELETE FROM audit_log WHERE seq = 2")
    audit._conn.commit()
    report = audit.verify_chain()
    assert not report.ok
    assert report.first_bad_seq == 3


def test_export_reload_round_trip(tmp_path: Path):
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    for i in range(4):
        source.record(_event(i))

    export_path = tmp_path / "audit-export.jsonl"
    assert source.export_jsonl(export_path) == 4

    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    assert target.import_jsonl(export_path) == 4

    report = target.verify_chain()
    assert report.ok and report.chained == 4
    assert target.read_all() == source.read_all()


def test_restore_refuses_non_empty_store(tmp_path: Path):
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    source.record(_event(0))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)

    non_empty = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    non_empty.record(_event(99))
    with pytest.raises(AuditChainError, match="non-empty"):
        non_empty.import_jsonl(export_path)


def test_restore_detects_transit_tamper(tmp_path: Path):
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    for i in range(2):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)

    doctored = export_path.read_text().replace("dossier 1", "DOCTORED")
    export_path.write_text(doctored)

    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    with pytest.raises(AuditChainError, match="altered in transit"):
        target.import_jsonl(export_path)


def test_worm_triggers_block_update_and_delete():
    audit = HashChainedAuditLog()
    audit.record(_event(1))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        audit._conn.execute("UPDATE audit_log SET event_json = '{}' WHERE seq = 1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        audit._conn.execute("DELETE FROM audit_log WHERE seq = 1")


def test_rows_without_chain_hashes_are_reported_as_not_intact(tmp_path: Path):
    """A store created before chaining existed upgrades in place: the old rows carry no
    hashes, so the trail is NOT verifiably intact and must not be reported as such.

    RED before the unchained-row fix: this returned ok=True with detail 'chain intact'.
    """
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_json TEXT NOT NULL)"
    )
    conn.execute("INSERT INTO audit_log (event_json) VALUES ('{}')")
    conn.commit()
    conn.close()

    audit = HashChainedAuditLog(str(db))
    audit.record(_event(1))
    report = audit.verify_chain()
    assert not report.ok
    assert report.legacy == 1
    assert report.chained == 1
    assert report.first_bad_seq == 1
    assert "no chain hashes" in report.detail


def test_inserted_unchained_row_is_not_reported_as_intact(tmp_path: Path):
    """Attack: INSERT a fabricated row with NULL hashes. The shipped triggers permit it
    (they block UPDATE/DELETE, not INSERT), the chained rows around it still link, and the
    row is returned by read_all() and written into the export.

    RED before the fix: verify_chain() returned ok=True, detail 'chain intact', so every
    programmatic consumer treated the fabricated record as verified history.
    """
    audit = HashChainedAuditLog(str(tmp_path / "audit.db"))
    for i in range(3):
        audit.record(_event(i))
    audit._conn.execute(
        "INSERT INTO audit_log (event_json, prev_hash, entry_hash) VALUES (?, NULL, NULL)",
        ('{"action":"fabricated"}',),
    )
    audit._conn.commit()

    report = audit.verify_chain()

    assert not report.ok
    assert report.entries == 4
    assert report.chained == 3
    assert report.legacy == 1
    assert "no chain hashes" in report.detail
    # And it stays caught: a later legitimate append does not restore 'chain intact'.
    audit.record(_event(9))
    assert not audit.verify_chain().ok


def test_appending_after_a_truncation_cannot_relaunder_the_anchor(tmp_path: Path):
    """Attack: truncate the tail, then let one ordinary append rewrite the anchor.

    RED before the fix: _write_anchor() ran on every append and re-anchored whatever the
    store then said, so verify_chain() went back to ok=True 'chain intact'. Detection held
    only if a verify happened to run inside the window between the tamper and the next
    append.
    """
    anchor = tmp_path / "elsewhere.anchor"
    audit = HashChainedAuditLog(str(tmp_path / "audit.db"), anchor_path=str(anchor))
    for i in range(3):
        audit.record(_event(i))
    audit._conn.execute("DROP TRIGGER audit_log_no_delete")
    audit._conn.execute("DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)")
    audit._conn.commit()
    anchored_before = anchor.read_text(encoding="utf-8")

    with pytest.raises(AuditChainError, match="refusing to append"):
        audit.record(_event(9))

    assert anchor.read_text(encoding="utf-8") == anchored_before
    assert not audit.verify_chain().ok


def test_a_missing_anchor_cannot_be_re_established_by_an_append(tmp_path: Path):
    """Deleting the witness must not let ordinary traffic quietly mint a fresh one.

    Re-establishing an anchor is an operator decision (reanchor()), never a side effect.
    """
    anchor = tmp_path / "elsewhere.anchor"
    audit = HashChainedAuditLog(str(tmp_path / "audit.db"), anchor_path=str(anchor))
    audit.record(_event(0))
    anchor.unlink()

    with pytest.raises(AuditChainError, match="anchor file is missing"):
        audit.record(_event(1))
    assert not anchor.exists()
    assert not audit.verify_chain().ok

    audit.reanchor()  # the deliberate operator action, after verifying out of band
    assert anchor.exists()
    assert audit.verify_chain().ok
    audit.record(_event(1))
    assert audit.verify_chain().ok


def _record_lines(export_path: Path) -> list[str]:
    """The export minus its anchor header: exactly what the pre-anchor format looked like."""
    return [line for line in export_path.read_text(encoding="utf-8").splitlines() if line.strip()][
        1:
    ]


def test_the_export_carries_the_anchor_header(tmp_path: Path):
    """The witness has to travel with the data, or it protects only the store it sits next to."""
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"), anchor_path=str(tmp_path / "a.json"))
    for i in range(3):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    assert source.export_jsonl(export_path) == 3  # the count is RECORDS, not lines

    lines = export_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4  # one anchor header + three records
    header = json.loads(lines[0])
    assert header["format"] == EXPORT_FORMAT
    assert header["anchor"]["seq"] == 3
    assert header["anchor"]["entry_hash"] == json.loads(lines[-1])["entry_hash"]
    assert "event" not in header  # an anchor line is distinguishable from an event line
    assert all("anchor" not in json.loads(line) for line in lines[1:])


def test_a_truncated_export_is_refused_on_import(tmp_path: Path):
    """The whole point. Drop the newest records from an export and the receiver must say so.

    RED before the anchor-header fix: export_jsonl() emitted only the event lines, so the
    external anchor stayed behind with the source. import_jsonl() re-verified the chain from
    the file it was handed, that shorter chain was internally perfect, and verify_chain()
    returned ok=True 'chain intact' over a history whose last two decisions had been deleted.
    """
    anchor = tmp_path / "elsewhere.anchor"
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"), anchor_path=str(anchor))
    for i in range(5):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)

    lines = export_path.read_text(encoding="utf-8").splitlines()
    export_path.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")  # drop 2 newest

    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    with pytest.raises(AuditChainError, match="anchored"):
        target.import_jsonl(export_path)

    # Refusing means nothing lands: no half-restored trail to be read back or re-exported.
    assert target.read_all() == []
    assert target.verify_chain().entries == 0


def test_an_untampered_export_round_trips_clean_and_adopts_the_anchor(tmp_path: Path):
    """The good path stays good, and the restored store inherits the SOURCE's witness."""
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"), anchor_path=str(tmp_path / "a.json"))
    for i in range(4):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    assert source.export_jsonl(export_path) == 4

    target_anchor = tmp_path / "b.json"
    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"), anchor_path=str(target_anchor))
    assert target.import_jsonl(export_path) == 4

    report = target.verify_chain()
    assert report.ok and report.chained == 4, report.detail
    assert target.read_all() == source.read_all()
    # Adopted, not minted: the target's anchor is the one that travelled in the export.
    assert json.loads(target_anchor.read_text(encoding="utf-8")) == json.loads(
        (tmp_path / "a.json").read_text(encoding="utf-8")
    )
    target.record(_event(9))  # and the restored store is appendable again
    assert target.verify_chain().ok


def test_a_pre_anchor_export_imports_but_is_reported_unanchored(tmp_path: Path):
    """Backward compatibility, without laundering: old exports load, and say what they are.

    An export written before the anchor header existed is still a valid chain, so it must
    still restore. What it can never be is "verified": nothing in it witnesses the tail, so
    reporting 'chain intact' would be the same false negative in a new coat.
    """
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    for i in range(3):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)
    legacy = tmp_path / "legacy-export.jsonl"
    legacy.write_text("\n".join(_record_lines(export_path)) + "\n", encoding="utf-8")

    target_anchor = tmp_path / "b.json"
    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"), anchor_path=str(target_anchor))
    assert target.import_jsonl(legacy) == 3  # it still imports

    report = target.verify_chain()
    assert not report.ok
    assert "no chain anchor" in report.detail
    assert not target_anchor.exists()  # and NO anchor was minted from the payload

    target.reanchor()  # the deliberate operator action, after checking out of band
    assert target.verify_chain().ok


def test_an_unanchored_import_stays_unanchored_without_an_anchor_file(tmp_path: Path):
    """A target with no anchor_path has no file to be missing, so the report must carry it."""
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    for i in range(3):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)
    legacy = tmp_path / "legacy-export.jsonl"
    legacy.write_text("\n".join(_record_lines(export_path)) + "\n", encoding="utf-8")

    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    target.import_jsonl(legacy)
    assert not target.verify_chain().ok
    # reanchor() with nowhere to write must not clear the finding either.
    target.reanchor()
    assert not target.verify_chain().ok


def test_being_unanchored_survives_a_re_export(tmp_path: Path):
    """One hop must not launder "nothing witnesses this" into "here is the witness"."""
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    for i in range(3):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)
    legacy = tmp_path / "legacy-export.jsonl"
    legacy.write_text("\n".join(_record_lines(export_path)) + "\n", encoding="utf-8")

    middle = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    middle.import_jsonl(legacy)
    onward = tmp_path / "onward.jsonl"
    middle.export_jsonl(onward)

    assert "anchor" not in onward.read_text(encoding="utf-8").splitlines()[0]
    third = HashChainedAuditLog(str(tmp_path / "audit-c.db"))
    third.import_jsonl(onward)
    assert not third.verify_chain().ok

    # After the operator takes responsibility, the export carries a header like any other.
    anchored_middle = HashChainedAuditLog(
        str(tmp_path / "audit-d.db"), anchor_path=str(tmp_path / "d.json")
    )
    anchored_middle.import_jsonl(legacy)
    anchored_middle.reanchor()
    anchored_middle.export_jsonl(onward)
    assert json.loads(onward.read_text(encoding="utf-8").splitlines()[0])["format"] == EXPORT_FORMAT


def test_an_interior_deletion_from_the_export_is_still_caught(tmp_path: Path):
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    for i in range(4):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)

    lines = export_path.read_text(encoding="utf-8").splitlines()
    export_path.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")

    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    with pytest.raises(AuditChainError, match="missing or reordered"):
        target.import_jsonl(export_path)
    assert target.read_all() == []


def test_a_second_anchor_line_is_refused(tmp_path: Path):
    """The header is the first line and only the first line: no smuggling a second witness."""
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    for i in range(2):
        source.record(_event(i))
    export_path = tmp_path / "export.jsonl"
    source.export_jsonl(export_path)
    lines = export_path.read_text(encoding="utf-8").splitlines()
    export_path.write_text(
        "\n".join([lines[0], lines[1], lines[0], lines[2]]) + "\n", encoding="utf-8"
    )

    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    with pytest.raises(AuditChainError, match="anchor"):
        target.import_jsonl(export_path)


def test_exporting_a_store_that_has_diverged_from_its_witness_is_refused(tmp_path: Path):
    """Export must not mint a header from a store its own anchor already contradicts."""
    anchor = tmp_path / "elsewhere.anchor"
    audit = HashChainedAuditLog(str(tmp_path / "audit.db"), anchor_path=str(anchor))
    for i in range(3):
        audit.record(_event(i))
    audit._conn.execute("DROP TRIGGER audit_log_no_delete")
    audit._conn.execute("DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)")
    audit._conn.commit()

    with pytest.raises(AuditChainError, match="refusing to export"):
        audit.export_jsonl(tmp_path / "export.jsonl")


def test_an_empty_trail_exports_an_anchored_assertion_that_it_is_empty(tmp_path: Path):
    source = HashChainedAuditLog(str(tmp_path / "audit-a.db"))
    export_path = tmp_path / "export.jsonl"
    assert source.export_jsonl(export_path) == 0

    target = HashChainedAuditLog(str(tmp_path / "audit-b.db"))
    assert target.import_jsonl(export_path) == 0
    assert target.verify_chain().ok


def test_external_anchor_detects_tail_truncation(tmp_path: Path):
    anchor = tmp_path / "audit-head.anchor"
    audit = HashChainedAuditLog(str(tmp_path / "audit.db"), anchor_path=str(anchor))
    for i in range(3):
        audit.record(_event(i))
    assert audit.verify_chain().ok

    # Truncate the tail: drop the newest row. The remaining chain is still internally valid,
    # so only the anchored head exposes the truncation.
    audit._conn.execute("DROP TRIGGER audit_log_no_delete")
    audit._conn.execute("DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)")
    audit._conn.commit()
    report = audit.verify_chain()
    assert not report.ok
    assert "anchor" in report.detail
