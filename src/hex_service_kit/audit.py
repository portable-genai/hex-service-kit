"""Append-only, hash-chained WORM audit log: the tamper-evident kernel primitive.

An SDK-free stand-in for a locked cloud WORM sink (Cloud Logging bucket, an immutable
object store) that records already-redacted audit events and supports read-back, tamper
verification, and an open-format export/restore.

**One policy, two storage adapters.** The chain rule, the external anchor rule and the
export format are storage-independent, so they live once in :class:`AnchoredChainStore`.
A storage adapter supplies five primitives (stage a row, read the rows back, count them,
name the newest chained one, commit or roll back) and inherits every guarantee below:

* :class:`HashChainedAuditLog` keeps the trail in an append-only SQLite table (or an
  in-memory table for ``:memory:``), with triggers that reject UPDATE and DELETE.
* :class:`JsonlFileAuditLog` keeps it in a plain append-only JSON Lines file, with no
  database engine involved. It is the offline / air-gapped archive adapter: the store is a
  file an auditor can copy to media and re-verify with SHA-256 and a JSON parser.

:class:`AuditStorePort` is the boundary those two sit behind, so a service binds an
evidence store the way it binds any other port.

Tamper evidence and portability: every record is cryptographically chained to
its predecessor, ``entry_hash = SHA-256(prev_hash || "\\n" || event_json)`` over the exact
stored JSON. The whole trail exports to (and restores from) JSON Lines: an anchor header
``{"anchor": {"seq", "entry_hash"}, "format"}`` on line 1, then one
``{"seq", "prev_hash", "entry_hash", "event"}`` object per record, an open documented format
that reloads into a fresh store with the chain verified line by line and the restored head
checked against the anchor that travelled with it. The audit-trail exit story is therefore a
file copy, not a product migration, and it is a copy ONTO A DIFFERENT ADAPTER: the format
carries ``seq`` but never depends on it, because ``seq`` is store-local (a SQLite rowid, a
line position) while the hashes chain over event content and survive the move.

**What the mechanism does and does not detect.** :meth:`AnchoredChainStore.verify_chain`
catches an in-place edit, an interior deletion, reordering, and any row that carries no chain
hashes (a fabricated INSERT, or a row written before chaining existed): such a row is
unverifiable, so the report is ``ok=False`` with the count in ``legacy``, never "chain
intact". It CANNOT by itself detect a truncated tail (dropping the newest N rows leaves a
valid shorter chain) or a full rewrite by an actor with write access to the store, because
the chain carries no secret. For those classes, anchor the chain head externally: pass
``anchor_path`` (keep it on a different volume / under different credentials) and every
append also writes ``{"seq", "entry_hash"}`` there, and :meth:`AnchoredChainStore.verify_chain`
cross-checks the stored head against the anchor. A managed WORM sink does not need this; it
provides non-rewritability itself.

**The anchor travels with the export.** An anchor that only ever sits beside its own store
protects that store and nothing downstream: hand someone an export with its newest lines
deleted and the shorter chain verifies perfectly, because the head it should have ended on
stayed behind. So :meth:`AnchoredChainStore.export_jsonl` writes the head as the export's
first line and :meth:`AnchoredChainStore.import_jsonl` checks the restored records against it
and refuses a mismatch, and never derives an anchor from the payload it was handed (an anchor
minted from a truncated payload witnesses only the truncation). An export written before the
header existed still restores, and :meth:`AnchoredChainStore.verify_chain` then reports it as
unanchored rather than intact.

What no export can settle by itself is a rewrite of the WHOLE file, header included: the
recipient needs the head over a second channel to catch that, which is why the anchor file is
worth handing over separately from the data.

**The anchor is not last-write-wins.** :meth:`AnchoredChainStore.record` refuses to append at
all when the store no longer matches the anchor (including when the anchor file has gone
missing), rather than re-anchoring the store's current contents. Otherwise a single ordinary
append after a tamper would launder it, and detection would hold only for whoever verified
inside the window between the two. Re-establishing an anchor is therefore a deliberate
operator action, :meth:`AnchoredChainStore.reanchor`, taken after checking the store out of
band.

Events are serialised with :func:`hex_service_kit.serialization.to_jsonable`, so any
dataclass / enum / datetime graph is accepted and a stored event round-trips through JSON
exactly. A store keeps any JSON-object event (not one fixed event shape) and takes an explicit
``anchor_path`` argument rather than reading any particular env var.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .serialization import to_jsonable

_GENESIS = ""  # prev_hash of the first chained record

EXPORT_FORMAT = "hex-service-kit.audit-jsonl.v1"


class AuditChainError(ValueError):
    """A restore/verify found records that do not extend the hash chain."""


@dataclass(frozen=True, slots=True)
class ChainReport:
    """Outcome of verifying the hash chain over the stored audit trail."""

    ok: bool
    entries: int  # total rows in the store
    chained: int  # rows carrying (and passing) chain hashes
    legacy: int  # rows with no chain hashes (unverifiable): any such row makes ok False
    first_bad_seq: int | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ChainScan:
    """Outcome of walking one stored chain segment, before any external cross-check.

    The row walk is the part every store shares, so it lives here once: a subclass that adds
    its own rooting (a retention watermark) or its own external checks calls
    :func:`scan_chain_rows` rather than restating what a broken link looks like.
    """

    ok: bool
    chained: int  # rows carrying (and passing) chain hashes
    legacy: int  # rows with no hashes: unverifiable, never "verified"
    head: str  # entry_hash the walk ended on (the expected next prev_hash)
    first_bad_seq: int | None = None
    detail: str = ""


class _ChainRow(Protocol):
    """Structural view of a stored row: ``seq``, ``event_json``, ``prev_hash``, ``entry_hash``."""

    def __getitem__(self, key: str, /) -> Any: ...


@runtime_checkable
class AuditStorePort(Protocol):
    """The storage boundary an evidence trail is written through, and carried out over.

    Declared so a service binds an audit store the way it binds any other port, and so the
    portability claim has something to be true OF: the same six operations, the same JSON
    Lines format, and a trail that leaves one implementation and lands whole on another.
    :class:`HashChainedAuditLog` and :class:`JsonlFileAuditLog` both satisfy it.
    """

    def record(self, event: object) -> None: ...

    def read_all(self) -> list[dict[str, Any]]: ...

    def verify_chain(self) -> ChainReport: ...

    def export_jsonl(self, path: str | Path) -> int: ...

    def import_jsonl(self, path: str | Path) -> int: ...

    def reanchor(self) -> None: ...


def scan_chain_rows(rows: Sequence[_ChainRow], *, expected_prev: str) -> ChainScan:
    """Re-derive every hash over ``rows`` (oldest first), starting from ``expected_prev``.

    A row whose hashes are NULL is counted in ``legacy`` and fails the scan: it may be a row
    written before chaining existed, or a fabricated INSERT (the WORM triggers block UPDATE
    and DELETE, not INSERT), and nothing in the store distinguishes the two. Either way the
    row is not verified, so the segment is not intact.
    """
    chained = legacy = 0
    first_unchained: int | None = None
    for row in rows:
        if row["entry_hash"] is None or row["prev_hash"] is None:
            legacy += 1
            if first_unchained is None:
                first_unchained = row["seq"]
            continue
        if row["prev_hash"] != expected_prev:
            return ChainScan(
                ok=False,
                chained=chained,
                legacy=legacy,
                head=expected_prev,
                first_bad_seq=row["seq"],
                detail=(
                    f"seq {row['seq']}: prev_hash does not extend the chain "
                    "(record inserted, deleted or reordered)"
                ),
            )
        if _entry_hash(row["prev_hash"], row["event_json"]) != row["entry_hash"]:
            return ChainScan(
                ok=False,
                chained=chained,
                legacy=legacy,
                head=expected_prev,
                first_bad_seq=row["seq"],
                detail=f"seq {row['seq']}: entry_hash mismatch (record altered in place)",
            )
        expected_prev = row["entry_hash"]
        chained += 1
    if legacy:
        return ChainScan(
            ok=False,
            chained=chained,
            legacy=legacy,
            head=expected_prev,
            first_bad_seq=first_unchained,
            detail=(
                f"seq {first_unchained}: row carries no chain hashes ({legacy} such row(s)): "
                "fabricated by direct INSERT, or written before chaining existed. Either way "
                "it is unverifiable, so the trail cannot be reported intact"
            ),
        )
    return ChainScan(ok=True, chained=chained, legacy=0, head=expected_prev)


def _canonical(payload: object) -> str:
    """The one canonical JSON encoding hashed, stored, exported and re-verified."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _anchor_header(entry: dict[str, Any], lineno: int) -> dict[str, Any]:
    """Read the anchor out of an export's header line, refusing a shape it cannot check."""
    stated = entry.get("format")
    if stated != EXPORT_FORMAT:
        raise AuditChainError(
            f"line {lineno}: export format {stated!r} is not {EXPORT_FORMAT!r}, so its anchor "
            "cannot be interpreted; restore it with the version that wrote it"
        )
    anchor = entry["anchor"]
    if not isinstance(anchor, dict) or not isinstance(anchor.get("entry_hash"), str):
        raise AuditChainError(
            f"line {lineno}: anchor header carries no readable chain head "
            '(expected {"anchor": {"seq": N, "entry_hash": "..."}})'
        )
    return anchor


def _entry_hash(prev_hash: str, event_json: str) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(b"\n")
    digest.update(event_json.encode("utf-8"))
    return digest.hexdigest()


class AnchoredChainStore:
    """The storage-independent half: the chain rule, the anchor rule and the export format.

    Everything here is about what a record IS and what a trail must prove, never about where
    the bytes land. A storage adapter implements the five primitives below and gets the
    append-only chain, the external anchor with its fail-closed append path, and the JSON
    Lines export/restore unchanged. Two adapters ship with the kit
    (:class:`HashChainedAuditLog` on SQLite, :class:`JsonlFileAuditLog` on a flat file); a
    third, onto whatever an institution already runs, implements the same five.

    Splitting it this way is what makes the portability claim testable at all. While export
    and reload shared a single storage implementation, a field the writer quietly dropped was
    a field the reader never missed, and the round trip agreed with itself.
    """

    def __init__(self, *, anchor_path: str = "") -> None:
        # Serialises the append-only single-writer access. A sync web endpoint under an ASGI
        # worker threadpool calls record() from worker threads other than the one that opened
        # the store, so without this a cross-thread record() can drop a WORM event.
        self._lock = threading.Lock()
        self._anchor_path = anchor_path.strip()
        # Set by import_jsonl() when the export carried no anchor header: the trail loaded, but
        # nothing external witnesses its tail, so verify_chain() must not call it intact.
        self._unanchored_restore = False

    # ------------------------------------------------------------------ #
    # Storage primitives: the whole of what an adapter has to supply
    # ------------------------------------------------------------------ #
    def _append_row(self, event_json: str, prev_hash: str, entry_hash: str) -> None:
        """Stage one row at the end of the trail, to land on the next :meth:`_commit`."""
        raise NotImplementedError

    def _all_rows(self) -> Sequence[_ChainRow]:
        """Every committed row, oldest first, keyed ``seq`` / ``event_json`` / the two hashes.

        Reads through to the underlying store rather than any cache: a verify has to see the
        bytes as they are now, including an edit made behind this process's back.
        """
        raise NotImplementedError

    def _row_count(self) -> int:
        """How many rows the store holds, without needing them to be readable as records."""
        raise NotImplementedError

    def _newest_chained(self) -> tuple[int, str] | None:
        """``(seq, entry_hash)`` of the newest row carrying a hash, or ``None`` if there is none."""
        raise NotImplementedError

    def _commit(self) -> None:
        """Durably land every staged row."""
        raise NotImplementedError

    def _rollback(self) -> None:
        """Discard every staged row: refusing means nothing lands, not "most of it lands"."""
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #
    def record(self, event: object) -> None:
        """Append one immutable, already-redacted audit record (no update / delete).

        ``event`` is any object :func:`to_jsonable` renders to a JSON object (a dataclass, or
        a plain ``dict``); a value that serialises to a non-object is a programming error.
        """
        payload = to_jsonable(event)
        if not isinstance(payload, dict):
            raise TypeError(
                f"audit event must serialise to a JSON object, got {type(payload).__name__}"
            )
        event_json = _canonical(payload)
        with self._lock:
            self._assert_anchor_continuity()
            prev_hash = self._head_hash()
            self._append_row(event_json, prev_hash, _entry_hash(prev_hash, event_json))
            self._commit()
            self._write_anchor()

    # ------------------------------------------------------------------ #
    # Chain head + the external anchor
    # ------------------------------------------------------------------ #
    def _head_hash(self) -> str:
        """The newest chained ``entry_hash``, i.e. the ``prev_hash`` the next append uses."""
        newest = self._newest_chained()
        return newest[1] if newest is not None else _GENESIS

    def _anchor_payload(self) -> dict[str, Any] | None:
        """What to write into the anchor file, or ``None`` when there is nothing to anchor.

        A subclass with more externally-witnessed state (a retention watermark, say) adds its
        keys here and cross-checks them in :meth:`_anchor_mismatch`, so the written shape and
        the checked shape can never drift apart.
        """
        newest = self._newest_chained()
        if newest is None:
            return None
        return {"seq": newest[0], "entry_hash": newest[1]}

    def _write_anchor(self) -> bool:
        """Persist the current chain head to the external anchor file, when configured.

        The anchor is what turns "valid chain" into "the SAME chain": keep it on a different
        volume / under different credentials than the store so truncating or rewriting the
        store cannot silently update the anchored head too. Callers on the append path
        must have passed :meth:`_assert_anchor_continuity` first, so this only ever advances
        an anchor the store still agrees with. Returns whether a file was actually written.
        """
        if not self._anchor_path:
            return False
        payload = self._anchor_payload()
        if payload is None:
            return False
        self._persist_anchor(payload)
        return True

    def _persist_anchor(self, payload: dict[str, Any]) -> None:
        """Write one anchor payload out, whether derived from this store or received with an
        import. Restoring adopts the anchor that travelled in the export rather than deriving
        a new one from the payload being imported, which would witness only itself.
        """
        if not self._anchor_path:
            return
        Path(self._anchor_path).write_text(_canonical(payload) + "\n", encoding="utf-8")

    def _anchor_mismatch(self, anchor: dict[str, Any]) -> str:
        """Describe how ``anchor`` disagrees with the store right now; ``""`` if it agrees."""
        if str(anchor.get("entry_hash") or "") != self._head_hash():
            return (
                f"chain head does not match the external anchor "
                f"(anchored seq {anchor.get('seq')}): tail truncated or rewritten"
            )
        return ""

    def _anchor_disagreement(self) -> str:
        """The one place that answers "does the external witness still match the store?".

        Both :meth:`verify_chain` and the append path ask this exact question, so a witness
        that is missing, unreadable or degraded cannot be loud in one and silent in the other.
        """
        if not self._anchor_path:
            return ""
        path = Path(self._anchor_path)
        if not path.exists():
            if self._head_hash() == _GENESIS:
                return ""  # nothing has ever been anchored: the first append establishes it
            return (
                "external anchor file is missing: the chain head cannot be cross-checked "
                f"({self._anchor_path})"
            )
        try:
            anchor = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return f"external anchor file cannot be read ({self._anchor_path}): {exc}"
        if not isinstance(anchor, dict):
            return f"external anchor file is not a JSON object ({self._anchor_path})"
        return self._anchor_mismatch(anchor)

    def _unanchored_restore_problem(self) -> str:
        """Why a trail restored from a pre-anchor export cannot be reported intact.

        Not part of :meth:`_anchor_disagreement`, because it is not a divergence from a
        witness: there is no witness. It is a reporting fact about this store's provenance,
        so it makes :meth:`verify_chain` honest without refusing ordinary appends.
        """
        if not self._unanchored_restore:
            return ""
        return (
            "restored from an export that carried no chain anchor (pre-anchor export format): "
            "the tail has no external witness here, so an export with its newest records "
            "dropped cannot be told from the whole trail. Check the trail against the source "
            "out of band, then call reanchor()"
        )

    def _assert_anchor_continuity(self) -> None:
        """Fail closed instead of re-anchoring a store that has diverged from its witness."""
        problem = self._anchor_disagreement()
        if problem:
            raise AuditChainError(
                f"refusing to append: {problem}. Appending would rewrite the anchor from the "
                "store as it now stands and launder the divergence; verify the store out of "
                "band, then call reanchor() deliberately."
            )

    def reanchor(self) -> None:
        """Deliberately (re)establish the external anchor from the store as it now stands.

        The operator escape hatch, never reached from the append path: it asserts nothing
        about the past, so use it only after verifying the store's integrity out of band
        (for example against an exported trail held elsewhere). It also settles the
        "restored from an unanchored export" finding, because that is the same decision:
        an operator taking responsibility for a head nothing external witnessed. It only
        settles it if an anchor file was really written, so a store with no ``anchor_path``
        cannot clear the finding by calling a method that writes nothing.
        """
        with self._lock:
            if self._write_anchor():
                self._unanchored_restore = False

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    def read_all(self) -> list[dict[str, Any]]:
        """Read back every stored event (oldest first) for inspection / assertions."""
        with self._lock:
            rows = self._all_rows()
        return [json.loads(row["event_json"]) for row in rows]

    # ------------------------------------------------------------------ #
    # Tamper evidence + open-format export / restore
    # ------------------------------------------------------------------ #
    def verify_chain(self) -> ChainReport:
        """Re-derive every hash from the stored bytes and confirm the chain links."""
        with self._lock:
            try:
                rows = self._all_rows()
            except AuditChainError as exc:
                # A store this adapter cannot even parse into records is not an exception to
                # raise past a verifier: "unreadable" is one of the answers verify owes.
                return ChainReport(
                    ok=False, entries=self._row_count(), chained=0, legacy=0, detail=str(exc)
                )
            scan = scan_chain_rows(rows, expected_prev=_GENESIS)
            if not scan.ok:
                return ChainReport(
                    ok=False,
                    entries=len(rows),
                    chained=scan.chained,
                    legacy=scan.legacy,
                    first_bad_seq=scan.first_bad_seq,
                    detail=scan.detail,
                )
            # Cross-check the external witness (when configured): a truncated tail leaves a
            # perfectly valid shorter chain, which only the anchor can expose.
            problem = self._unanchored_restore_problem() or self._anchor_disagreement()
        if problem:
            return ChainReport(
                ok=False,
                entries=len(rows),
                chained=scan.chained,
                legacy=scan.legacy,
                first_bad_seq=None,
                detail=problem,
            )
        return ChainReport(
            ok=True,
            entries=len(rows),
            chained=scan.chained,
            legacy=scan.legacy,
            detail="chain intact",
        )

    def export_jsonl(self, path: str | Path) -> int:
        """Export the trail to JSON Lines, anchor header first, then one line per record.

        Line 1 is the anchor header, ``{"anchor": {"seq", "entry_hash"}, "format"}``: the
        chain head this export commits to. Every later line is one record,
        ``{"seq", "prev_hash", "entry_hash", "event"}``, unchanged from the pre-anchor
        format. The two are told apart by key, not by position alone: a header carries
        ``anchor`` and no ``event``, a record carries ``event`` and no ``anchor`` (a recorded
        event's own keys sit nested under ``event``, so they cannot collide). The event object
        is the :func:`to_jsonable` form of the recorded event.

        Both hashes and the head travel, so a receiving team re-verifies the whole file with
        SHA-256 and a JSON parser and nothing from this codebase: read the head from line 1,
        walk the records deriving ``entry_hash = SHA-256(prev_hash || "\\n" || event_json)``
        over the canonical event JSON, and check the last ``entry_hash`` against the head. An
        export whose newest lines were dropped fails that last check, which is exactly the
        case the chain alone cannot see. It does not defend against a rewrite of the whole
        file, header included: for that the recipient needs the head over a second channel.

        Refuses to export a store that its own external anchor already contradicts, for the
        same reason :meth:`record` refuses to append to one: writing a header derived from
        the store as it now stands would hand the recipient a self-consistent copy of a trail
        this store's witness says is not whole.

        A store restored from a pre-anchor export exports without a header, so being
        unanchored travels too. Re-exporting such a trail with a head derived from it would
        launder "nothing witnesses this" into "here is the witness" over one hop, with no
        operator deciding anything. :meth:`reanchor` is that decision, and after it the export
        carries a header like any other. Returns the number of RECORDS written.
        """
        with self._lock:
            problem = self._anchor_disagreement()
            if problem:
                raise AuditChainError(
                    f"refusing to export: {problem}. The export header would be derived from "
                    "the store as it now stands, so the recipient would receive a "
                    "self-consistent trail with the divergence washed out; verify the store "
                    "out of band, then call reanchor() deliberately."
                )
            rows = self._all_rows()
            # An empty trail still exports a header: "this trail is empty" is a claim worth
            # anchoring, since the alternative is an empty file that says nothing at all.
            anchor = self._anchor_payload() or {"seq": 0, "entry_hash": _GENESIS}
            unanchored = self._unanchored_restore
        lines = [] if unanchored else [_canonical({"anchor": anchor, "format": EXPORT_FORMAT})]
        lines += [
            _canonical(
                {
                    "seq": row["seq"],
                    "prev_hash": row["prev_hash"],
                    "entry_hash": row["entry_hash"],
                    "event": json.loads(row["event_json"]),
                }
            )
            for row in rows
        ]
        Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return len(rows)

    def import_jsonl(self, path: str | Path) -> int:
        """Restore an exported trail into this (empty) store, re-verifying every link.

        The round-trip proof, and the point of the port: an export written by one adapter
        reloads on a DIFFERENT one with every field and the chain intact. Refuses a non-empty
        target (append-only stores do not merge), any record that fails hash verification, and
        any export whose records do not end on the head its own anchor header commits to. A
        refusal restores nothing at all: the half-walked rows are rolled back, so there is no
        partial trail to read back or re-export.

        The anchor that arrives with the export is adopted as this store's anchor; one is
        never derived from the payload being imported, which would witness only itself and
        make a truncated trail look whole. An export written before the header existed
        carries no anchor: it still restores, and :meth:`verify_chain` then reports the trail
        as unanchored rather than intact until an operator calls :meth:`reanchor`.

        Returns the count restored.
        """
        with self._lock:
            if self._row_count():
                raise AuditChainError(
                    "refusing to restore into a non-empty audit store (append-only); "
                    "point the store at a fresh path"
                )
            try:
                anchor, imported = self._restore_lines(Path(path).read_text(encoding="utf-8"))
            except Exception:
                self._rollback()  # refusing means nothing lands, not "most of it lands"
                raise
            self._commit()
            self._unanchored_restore = anchor is None
            if anchor is not None:
                self._persist_anchor(anchor)
        return imported

    def _restore_lines(self, text: str) -> tuple[dict[str, Any] | None, int]:
        """Walk one export, staging the records; return its anchor (if any) and the count.

        Caller holds the lock and owns the commit/rollback, so every way out of here that
        raises leaves the staged rows unlanded.
        """
        anchor: dict[str, Any] | None = None
        expected_prev = _GENESIS
        imported = 0
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise AuditChainError(f"line {lineno}: export line is not a JSON object")
            if "anchor" in entry:
                if anchor is not None or imported:
                    raise AuditChainError(
                        f"line {lineno}: a second anchor header, or an anchor header after the "
                        "records. The export carries exactly one, on its first line"
                    )
                anchor = _anchor_header(entry, lineno)
                continue
            event = entry.get("event") or {}
            prev_hash, entry_hash = entry.get("prev_hash"), entry.get("entry_hash")
            if prev_hash is None or entry_hash is None:
                raise AuditChainError(
                    f"line {lineno}: record has no chain hashes (pre-chaining legacy "
                    "export) and cannot be restored verifiably"
                )
            if prev_hash != expected_prev:
                raise AuditChainError(
                    f"line {lineno}: prev_hash does not extend the chain "
                    "(records missing or reordered)"
                )
            event_json = _canonical(event)
            if _entry_hash(prev_hash, event_json) != entry_hash:
                raise AuditChainError(
                    f"line {lineno}: entry_hash mismatch (record altered in transit)"
                )
            self._append_row(event_json, prev_hash, entry_hash)
            expected_prev = entry_hash
            imported += 1
        if anchor is not None and str(anchor["entry_hash"]) != expected_prev:
            raise AuditChainError(
                f"the restored records end at {expected_prev or '(empty trail)'}, but this "
                f"export is anchored to seq {anchor.get('seq')} / "
                f"{anchor['entry_hash'] or '(empty trail)'}: records are missing from the tail "
                "(the export was truncated or rewritten in transit)"
            )
        return anchor, imported


class HashChainedAuditLog(AnchoredChainStore):
    """Append-only, hash-chained audit store for already-redacted events, kept in SQLite.

    The serving-path adapter: indexed, transactional, and append-only IN THE STORE rather
    than by convention, because SQLite triggers reject UPDATE and DELETE. Pass ``:memory:``
    (the default) for a process-lifetime store, or a filesystem path for a durable one.
    """

    def __init__(self, path: str = ":memory:", *, anchor_path: str = "") -> None:
        super().__init__(anchor_path=anchor_path)
        self._path = path
        if path not in (":memory:", "") and not path.startswith("file:"):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # ``check_same_thread=False`` + the inherited lock: a sync web endpoint under an ASGI
        # worker threadpool calls record() from worker threads other than the one that opened
        # the connection, and without this a cross-thread record() raises (silently dropping
        # a WORM event).
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json TEXT NOT NULL,
                prev_hash TEXT,
                entry_hash TEXT
            )
            """
        )
        self._ensure_chain_columns()
        # WORM in the store, not just by convention: reject UPDATE/DELETE at the SQLite
        # layer. (An attacker with file access can drop the triggers, which is why the hash
        # chain + external head anchor exist on top; see the module docstring.)
        for verb in ("UPDATE", "DELETE"):
            self._conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS audit_log_no_{verb.lower()} "
                f"BEFORE {verb} ON audit_log BEGIN "
                f"SELECT RAISE(ABORT, 'audit_log is append-only (WORM): {verb} blocked'); "
                "END"
            )
        self._conn.commit()

    def _ensure_chain_columns(self) -> None:
        # A store created before chaining existed lacks the hash columns. Add them; the old
        # rows keep NULL hashes; verify_chain() counts them in 'legacy' and reports the
        # trail as NOT intact, because an unhashed row is indistinguishable from one a direct
        # INSERT fabricated.
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(audit_log)")}
        for column in ("prev_hash", "entry_hash"):
            if column not in columns:
                self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column} TEXT")

    # ------------------------------------------------------------------ #
    # Storage primitives (SQLite)
    # ------------------------------------------------------------------ #
    def _append_row(self, event_json: str, prev_hash: str, entry_hash: str) -> None:
        self._conn.execute(
            "INSERT INTO audit_log (event_json, prev_hash, entry_hash) VALUES (?, ?, ?)",
            (event_json, prev_hash, entry_hash),
        )

    def _all_rows(self) -> Sequence[_ChainRow]:
        return self._conn.execute(
            "SELECT seq, event_json, prev_hash, entry_hash FROM audit_log ORDER BY seq ASC"
        ).fetchall()

    def _row_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"])

    def _newest_chained(self) -> tuple[int, str] | None:
        row = self._conn.execute(
            "SELECT seq, entry_hash FROM audit_log WHERE entry_hash IS NOT NULL "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return None if row is None else (int(row["seq"]), str(row["entry_hash"]))

    def _commit(self) -> None:
        self._conn.commit()

    def _rollback(self) -> None:
        self._conn.rollback()


class JsonlFileAuditLog(AnchoredChainStore):
    """The same trail, kept as a plain append-only JSON Lines file with no database engine.

    The offline / air-gapped archive adapter, and the second side of the portability proof:
    a trail exported from SQLite reloads here (and back) with every field and the chain
    intact, which a round trip through one adapter cannot show. One line per record,
    ``{"prev_hash", "entry_hash", "event_json"}``, oldest first, where ``event_json`` is the
    exact canonical JSON string the chain hashes over and the line's POSITION in the file is
    its ``seq``. That is deliberately not the export's record shape: the store translates in
    both directions, so a passing round trip is a real conversion rather than a file copy.

    Two honest differences from :class:`HashChainedAuditLog`, both narrowing what this
    adapter enforces rather than what it proves:

    * **Append-only is a property of this code path, not of the filesystem.** There are no
      triggers to reject an overwrite; the adapter only ever opens the file in append mode.
      Anyone who can write the file can rewrite it, which is exactly why the hash chain and
      an ``anchor_path`` on separate storage carry the weight here. The detection story is
      otherwise identical, because it is the same chain and the same anchor.
    * **Reads parse the whole file**, so an append costs a read of the trail. This adapter is
      sized for exports, restores, archives and offline verification, not for a hot serving
      path; bind the SQLite adapter there.
    """

    def __init__(self, path: str | Path, *, anchor_path: str = "") -> None:
        super().__init__(anchor_path=anchor_path)
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)
        # Rows staged by _append_row, landed by _commit, dropped by _rollback. Nothing
        # reaches the file until the commit, so a refused restore leaves no partial trail.
        self._pending: list[str] = []

    # ------------------------------------------------------------------ #
    # Storage primitives (flat file)
    # ------------------------------------------------------------------ #
    def _append_row(self, event_json: str, prev_hash: str, entry_hash: str) -> None:
        self._pending.append(
            _canonical({"prev_hash": prev_hash, "entry_hash": entry_hash, "event_json": event_json})
        )

    def _all_rows(self) -> Sequence[_ChainRow]:
        rows: list[dict[str, Any]] = []
        for seq, line in enumerate(self._lines(), start=1):
            try:
                entry = json.loads(line)
            except ValueError as exc:
                raise AuditChainError(
                    f"store line {seq}: not readable JSON, so this record cannot be verified "
                    f"({self._path}): {exc}"
                ) from exc
            if not isinstance(entry, dict) or not isinstance(entry.get("event_json"), str):
                raise AuditChainError(
                    f"store line {seq}: not an audit record (expected an object with "
                    f'"event_json", "prev_hash" and "entry_hash") ({self._path})'
                )
            rows.append(
                {
                    # seq is the line's position: store-local, exactly like a SQLite rowid,
                    # and re-derived on read so it can never disagree with the file.
                    "seq": seq,
                    "event_json": entry["event_json"],
                    "prev_hash": entry.get("prev_hash"),
                    "entry_hash": entry.get("entry_hash"),
                }
            )
        return rows

    def _row_count(self) -> int:
        return len(self._lines())

    def _newest_chained(self) -> tuple[int, str] | None:
        for seq, line in reversed(list(enumerate(self._lines(), start=1))):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("entry_hash"), str):
                return seq, entry["entry_hash"]
        return None

    def _commit(self) -> None:
        if not self._pending:
            return
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write("".join(line + "\n" for line in self._pending))
            handle.flush()
            os.fsync(handle.fileno())  # the append is not a WORM write until it is durable
        self._pending.clear()

    def _rollback(self) -> None:
        self._pending.clear()

    def _lines(self) -> list[str]:
        """The store's non-blank lines, read fresh: the file is the store, not a cache of it."""
        if not self._path.exists():
            return []
        return [
            line for line in self._path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
