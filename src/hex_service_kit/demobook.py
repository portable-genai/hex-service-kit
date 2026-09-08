"""One fictional record book, served identically by the laptop store and the managed one.

A system that demonstrates relevance to a customer's record needs records to be relevant to.
Every repository here that has such a demo used to ship its book as a Python module the local
adapter imported, and nothing carried that book to the table the managed adapter reads. The
consequences were the same in each: the deployed path had never held a row, the laptop and
the deployment could not be compared because they were about different customers, and a
change to one moved what the demo narrated without moving what the gate measured.

This module is that pattern, written once. A repository supplies its own tables and its own
rows; what it gets here is the part that was identical everywhere and worth being identical:

* **The book.** Newline-delimited JSON, one file per managed table, each row's keys in that
  table's column order. Files rather than code so the loader, the local store and the tests
  read the same bytes.
* **The overwrite guard.** :func:`may_overwrite`, called by BOTH the local store and the
  managed loader, so the rule that a demo loader may never truncate a real book is proved in
  one place instead of drifting between two.
* **The local store.** :class:`DuckDbStore` holds the same tables the managed dataset holds,
  in the same column order, and self-seeds from the book when it is empty. DuckDB is an
  embedded engine in a wheel: no service, no credentials, nothing to start, so an offline
  gate stays offline while the store it exercises is still SQL.
* **The tenant rule.** :func:`retenant` exists because getting this wrong is silent. On a
  deployment the tenant is whatever the identity adapter resolves, usually an IAP hosted
  domain; rows loaded under any other value are invisible to every real user, because
  entitlement filtering is fail-closed, and an invisible row reads exactly like an empty
  dataset. So a loader takes the tenant as a required argument and never defaults it.

The core here is standard library only. DuckDB is imported lazily inside
:class:`DuckDbStore`, and declared by the ``demobook`` extra, so a consumer that only wants
the book reader and the guard installs no database at all.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

__all__ = [
    "BookError",
    "DuckDbStore",
    "NdjsonBook",
    "Table",
    "as_date",
    "may_overwrite",
    "retenant",
]


class BookError(ValueError):
    """The shipped book violates one of its own invariants.

    Raised before anything is served or loaded, so a hand edit that breaks the book fails at
    the store that reads it rather than as a briefing about a customer who does not add up.
    """


# --------------------------------------------------------------------------- #
# The table declaration
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class Table:
    """One table of a book: its name, its columns in order, and their local types.

    ``columns`` is the contract. It is the order rows are written in, the order the local
    DDL declares, and the list a contract test holds against the repository's own Terraform,
    which is how a column the managed adapter selects and the schema never declared gets
    caught before a deployment meets it.

    ``date_columns`` are named because JSON has no date: a value arrives as a string and has
    to become a ``date`` for the local store to compare or sort it the way BigQuery would.
    """

    name: str
    columns: tuple[str, ...]
    types: Mapping[str, str] = field(default_factory=dict)
    primary_key: tuple[str, ...] = ()
    date_columns: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.name.isidentifier():
            raise BookError(f"table name {self.name!r} is not a plain identifier")
        if not self.columns:
            raise BookError(f"table {self.name!r} declares no columns")
        unknown = sorted(set(self.types) - set(self.columns))
        if unknown:
            raise BookError(f"table {self.name!r} types name undeclared columns: {unknown}")
        missing = sorted(set(self.primary_key) - set(self.columns))
        if missing:
            raise BookError(f"table {self.name!r} primary key names undeclared columns: {missing}")
        stray = sorted(self.date_columns - set(self.columns))
        if stray:
            raise BookError(f"table {self.name!r} date columns are undeclared: {stray}")
        # A column named as a date must BE one in the store, or the coercion this class
        # performs writes a `date` into a TEXT column and DuckDB stores its repr. The store
        # then answers with a string where the managed store answers with a date, which is
        # exactly the kind of difference that makes two stores incomparable while both
        # "work". Found by this check failing on its own test fixture.
        for column in sorted(self.date_columns):
            declared = self.types.get(column, "TEXT").upper()
            if "DATE" not in declared and "TIMESTAMP" not in declared:
                raise BookError(
                    f"table {self.name!r} column {column!r} is a date column but is typed "
                    f"{declared!r}; declare it DATE so the store holds a date"
                )

    def ddl(self) -> str:
        """The CREATE TABLE body, columns in declaration order."""
        parts = [f"{column} {self.types.get(column, 'TEXT')}" for column in self.columns]
        if self.primary_key:
            parts.append(f"PRIMARY KEY ({', '.join(self.primary_key)})")
        return ", ".join(parts)


# --------------------------------------------------------------------------- #
# The book
# --------------------------------------------------------------------------- #
def as_date(value: Any) -> date | None:
    """Coerce an ISO date string (or ``None``) to a :class:`date`."""
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


class NdjsonBook:
    """A book of newline-delimited JSON files, one per table, shipped inside a package.

    Reading is deliberately dumb: parse, check the row is an object, keep file order. Every
    rule beyond that belongs to the repository whose book it is, because "a client's weights
    sum to one" and "a channel benchmark has a positive CPM" are not facts this module can
    know. What it does own is that a row is a row and that the manifest says what the book is.
    """

    #: The table every book carries, describing itself. ``fictional`` is what the overwrite
    #: guard reads, which is why it is required rather than assumed.
    MANIFEST = Table(
        name="book_manifest",
        columns=(
            "book_version",
            "as_of_date",
            "fictional",
            "loaded_at",
            "source_commit",
            "tenant",
        ),
        types={
            "book_version": "TEXT NOT NULL",
            "as_of_date": "DATE NOT NULL",
            "fictional": "BOOLEAN NOT NULL",
            "loaded_at": "TIMESTAMP",
            "source_commit": "TEXT",
            "tenant": "TEXT NOT NULL",
        },
        date_columns=frozenset({"as_of_date"}),
    )

    def __init__(self, package: str, tables: Sequence[Table]) -> None:
        """``package`` is the dotted package holding the ``.ndjson`` files."""
        self._package = package
        self._tables = tuple(t for t in tables if t.name != self.MANIFEST.name)
        if len({t.name for t in self._tables}) != len(self._tables):
            raise BookError("two tables in this book share a name")
        # The manifest is looked up like any other table but is never one of the repository's
        # own: it is appended last on load, because it records the load that wrote the rest.
        self._by_name = {t.name: t for t in self._tables} | {self.MANIFEST.name: self.MANIFEST}

    @property
    def tables(self) -> tuple[Table, ...]:
        """The tables in LOAD order: a referenced table before the rows referencing it."""
        return self._tables

    def table(self, name: str) -> Table:
        try:
            return self._by_name[name]
        except KeyError:
            raise BookError(f"this book declares no table {name!r}") from None

    def rows(self, table: str) -> list[dict[str, Any]]:
        """The rows of one shipped table, as parsed objects, in file order."""
        self.table(table)  # refuse a name this book does not declare
        text = (resources.files(self._package) / f"{table}.ndjson").read_text(encoding="utf-8")
        out: list[dict[str, Any]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                raise BookError(f"{table}.ndjson line {number}: not a JSON object")
            out.append(parsed)
        return out

    def manifest(self) -> dict[str, Any]:
        """The single manifest row: version, as-of date, and whether this book is fictional."""
        found = self.rows(self.MANIFEST.name)
        if len(found) != 1:
            raise BookError(
                f"{self.MANIFEST.name}.ndjson must hold exactly one row, found {len(found)}"
            )
        return found[0]

    def validate(self) -> None:
        """Check what this module can know: every row has every column, and the manifest.

        Repository-specific invariants belong in the repository, and this is deliberately not
        a hook for them: a book that passes here is well-formed, not correct.
        """
        for table in self.load_order():
            declared = set(table.columns)
            for index, row in enumerate(self.rows(table.name), start=1):
                extra = sorted(set(row) - declared)
                if extra:
                    raise BookError(f"{table.name}.ndjson row {index} has undeclared {extra}")
        if self.manifest().get("fictional") is not True:
            raise BookError(f"{self.MANIFEST.name} must state fictional: true")

    def load_order(self) -> tuple[Table, ...]:
        """Every table plus the manifest last: it records the load that wrote the others."""
        return (*self._tables, self.MANIFEST)


# --------------------------------------------------------------------------- #
# The overwrite guard, shared by the local store and the managed loader
# --------------------------------------------------------------------------- #
def may_overwrite(
    row_counts: Mapping[str, int], manifest_rows: Iterable[Mapping[str, Any]]
) -> bool:
    """Whether a store holding ``row_counts`` may be truncated and reloaded with a demo book.

    True when every table is empty, or when the store's own manifest declares what it holds
    fictional. False otherwise, because a populated store without that declaration is
    somebody's real book and a demo loader must never be the thing that truncates it.

    Called by both stores on purpose. A guard implemented twice is a guard that eventually
    says different things in the two places, and the place it says yes is the one that
    matters.
    """
    if all(count == 0 for count in row_counts.values()):
        return True
    return any(row.get("fictional") is True for row in manifest_rows)


def retenant(
    rows: Sequence[Mapping[str, Any]],
    tenant: str,
    *,
    key: str = "tenant",
    keep_separate: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Stamp the deployment's tenant onto every row that carries one.

    On a deployment the tenant is what the identity adapter resolved, usually a hosted
    domain. Rows under any other value are invisible to every real user because entitlement
    filtering is fail-closed, and an invisible row is indistinguishable from an empty
    dataset, so this is never defaulted and never inferred.

    ``keep_separate`` maps an identifier to a suffix for rows that must NOT be folded into
    the main tenant: a book usually ships one record belonging to a second tenant precisely
    to prove that a user cannot reach another tenant's data, and quietly re-stamping it would
    delete the only evidence that gate does anything.
    """
    if not tenant.strip():
        raise BookError("a tenant is required: rows under no tenant are unreachable")
    separate = dict(keep_separate or {})
    out: list[dict[str, Any]] = []
    for row in rows:
        if key not in row:
            out.append(dict(row))
            continue
        suffix = next((s for ident, s in separate.items() if ident in row.values()), "")
        out.append(dict(row, **{key: f"{tenant}{suffix}"}))
    return out


# --------------------------------------------------------------------------- #
# The local store
# --------------------------------------------------------------------------- #
class _Connection(Protocol):  # pragma: no cover - structural typing only
    def execute(self, query: str, parameters: object = ...) -> Any: ...
    def executemany(self, query: str, parameters: object) -> Any: ...
    def close(self) -> None: ...


class DuckDbStore:
    """The laptop's copy of a managed dataset: same tables, same column order, same rows.

    Holding the SAME shape as the managed store is the whole point. Two stores that merely
    both work are two stores nobody can compare; two stores over one book and one column
    order can be run side by side and their answers held against each other, which is what
    a portability claim has to mean to be worth anything.

    Self-seeds when empty, and leaves a populated store alone whoever wrote it. That second
    half matters for a demo as much as for a real book: re-seeding on every open would
    discard the records an audience registered in an earlier run of the same demo.
    """

    def __init__(self, book: NdjsonBook, path: str) -> None:
        self._book = book
        self._path = path
        self._conn = self._connect(path)
        self._init_schema()
        self._maybe_seed()

    @staticmethod
    def _connect(path: str) -> _Connection:
        import duckdb  # noqa: PLC0415 - lazy: the kit core installs no database

        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        return duckdb.connect(path)

    @property
    def connection(self) -> Any:
        """The open connection, for a repository's own queries against its own schema."""
        return self._conn

    @property
    def path(self) -> str:
        return self._path

    def _init_schema(self) -> None:
        for table in self._book.load_order():
            self._conn.execute(f"CREATE TABLE IF NOT EXISTS {table.name} ({table.ddl()})")

    def scalar(self, sql: str) -> Any:
        """The first column of the first row, or ``None`` when the query returned none."""
        row = self._conn.execute(sql).fetchone()
        return None if row is None else row[0]

    def row_counts(self) -> dict[str, int]:
        return {
            table.name: int(self.scalar(f"SELECT count(*) FROM {table.name}") or 0)
            for table in self._book.load_order()
        }

    def manifest_rows(self) -> list[dict[str, Any]]:
        columns = self._book.MANIFEST.columns
        return [
            dict(zip(columns, row, strict=True))
            for row in self._conn.execute(f"SELECT * FROM {self._book.MANIFEST.name}").fetchall()
        ]

    def _maybe_seed(self) -> None:
        if all(count == 0 for count in self.row_counts().values()):
            self.seed_shipped_book()

    def seed_shipped_book(self) -> None:
        """Replace this store's contents with the shipped book, if the guard allows it."""
        self._book.validate()
        counts = self.row_counts()
        if not may_overwrite(counts, self.manifest_rows()):
            held = ", ".join(f"{name}={n}" for name, n in sorted(counts.items()) if n)
            raise PermissionError(
                f"refusing to seed {self._path}: it holds rows ({held}) and its manifest does "
                "not say they are fictional"
            )
        for table in reversed(self._book.load_order()):
            self._conn.execute(f"DELETE FROM {table.name}")
        for table in self._book.load_order():
            self.insert(table, self._book.rows(table.name))

    def insert(self, table: Table, rows: Sequence[Mapping[str, Any]]) -> None:
        """Insert rows, columns in the table's declared order and dates coerced."""
        if not rows:
            return
        placeholders = ", ".join("?" for _ in table.columns)
        values = [
            [
                as_date(row.get(column)) if column in table.date_columns else row.get(column)
                for column in table.columns
            ]
            for row in rows
        ]
        self._conn.executemany(
            f"INSERT INTO {table.name} ({', '.join(table.columns)}) VALUES ({placeholders})",
            values,
        )

    def close(self) -> None:
        self._conn.close()
