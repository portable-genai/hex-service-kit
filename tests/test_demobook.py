"""The demo-book pattern: one book, two stores, and a guard that refuses a real one.

Each test here names the defect it exists to catch, because every one of them was found by
execution in a consuming repository rather than imagined:

* a managed adapter that selected a column its own Terraform never declared, so the deployed
  path failed at the first request while every offline gate stayed green;
* a loader that would have truncated whatever it was pointed at;
* rows loaded under a tenant no real user resolves to, which reads exactly like an empty
  dataset because entitlement filtering is fail-closed;
* a store that re-seeded on every open, discarding what an audience had registered.

The DuckDB half is skipped when the ``demobook`` extra is absent, and the skip is loud: the
kit core installs no database on purpose, so a silent skip here would be indistinguishable
from a store that works.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from hex_service_kit.demobook import (
    BookError,
    NdjsonBook,
    Table,
    as_date,
    may_overwrite,
    retenant,
)

duckdb = pytest.importorskip("duckdb", reason="the demobook extra is not installed")

from hex_service_kit.demobook import DuckDbStore  # noqa: E402

_WIDGETS = Table(
    name="widgets",
    columns=("widget_id", "name", "tenant", "made_on"),
    types={
        "widget_id": "TEXT NOT NULL",
        "name": "TEXT NOT NULL",
        "tenant": "TEXT NOT NULL",
        "made_on": "DATE",
    },
    primary_key=("widget_id",),
    date_columns=frozenset({"made_on"}),
)


_BOOKS = iter(range(1, 1000))


def _write_book(root: Path, widgets: list[dict], manifest: dict | None = None) -> str:
    """Write a two-table book into an importable package and return its dotted name.

    The package name is unique per call because ``importlib`` caches by name: a second book
    written under a name already imported is never read, and the test silently asserts
    against the first one's rows.
    """
    name = f"sample_book_{next(_BOOKS)}"
    package = root / name
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "widgets.ndjson").write_text(
        "".join(json.dumps(row) + "\n" for row in widgets), encoding="utf-8"
    )
    row = manifest or {
        "book_version": "test-v1",
        "as_of_date": "2026-09-01",
        "fictional": True,
        "loaded_at": None,
        "source_commit": None,
        "tenant": "demo-bank",
    }
    (package / "book_manifest.ndjson").write_text(json.dumps(row) + "\n", encoding="utf-8")
    return name


@pytest.fixture
def book(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> NdjsonBook:
    monkeypatch.syspath_prepend(str(tmp_path))
    name = _write_book(
        tmp_path,
        [
            {
                "widget_id": "w-1",
                "name": "First",
                "tenant": "demo-bank",
                "made_on": "2026-01-02",
            },
            {"widget_id": "w-2", "name": "Second", "tenant": "other-bank", "made_on": None},
        ],
    )
    return NdjsonBook(name, [_WIDGETS])


# --------------------------------------------------------------------------- #
# The table declaration is the contract
# --------------------------------------------------------------------------- #
def test_a_table_refuses_a_declaration_that_contradicts_itself() -> None:
    with pytest.raises(BookError, match="no columns"):
        Table(name="t", columns=())
    with pytest.raises(BookError, match="undeclared columns"):
        Table(name="t", columns=("a",), types={"b": "TEXT"})
    with pytest.raises(BookError, match="primary key"):
        Table(name="t", columns=("a",), primary_key=("b",))
    with pytest.raises(BookError, match="date columns"):
        Table(name="t", columns=("a",), date_columns=frozenset({"b"}))


def test_a_date_column_typed_as_text_is_refused() -> None:
    """Otherwise the store answers with a string where the managed store answers with a date."""
    with pytest.raises(BookError, match="declare it DATE"):
        Table(name="t", columns=("d",), types={"d": "TEXT"}, date_columns=frozenset({"d"}))
    Table(name="t", columns=("d",), types={"d": "DATE"}, date_columns=frozenset({"d"}))


def test_the_ddl_keeps_the_declared_column_order() -> None:
    """Order is load-bearing: it is what the managed schema is held against."""
    ddl = _WIDGETS.ddl()
    assert ddl.index("widget_id") < ddl.index("name") < ddl.index("tenant") < ddl.index("made_on")
    assert "PRIMARY KEY (widget_id)" in ddl


# --------------------------------------------------------------------------- #
# The book
# --------------------------------------------------------------------------- #
def test_rows_come_back_in_file_order_and_a_missing_table_is_refused(book: NdjsonBook) -> None:
    assert [row["widget_id"] for row in book.rows("widgets")] == ["w-1", "w-2"]
    with pytest.raises(BookError, match="declares no table"):
        book.rows("nope")


def test_a_row_with_an_undeclared_column_fails_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    name = _write_book(
        tmp_path,
        [{"widget_id": "w-1", "name": "First", "tenant": "t", "made_on": None, "colour": "red"}],
    )
    with pytest.raises(BookError, match="undeclared"):
        NdjsonBook(name, [_WIDGETS]).validate()


def test_a_book_that_does_not_call_itself_fictional_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The manifest is the guard's input, so a book may not simply omit the claim."""
    monkeypatch.syspath_prepend(str(tmp_path))
    name = _write_book(
        tmp_path,
        [{"widget_id": "w-1", "name": "First", "tenant": "t", "made_on": None}],
        manifest={
            "book_version": "v",
            "as_of_date": "2026-09-01",
            "fictional": False,
            "loaded_at": None,
            "source_commit": None,
            "tenant": "t",
        },
    )
    with pytest.raises(BookError, match="fictional"):
        NdjsonBook(name, [_WIDGETS]).validate()


def test_two_tables_may_not_share_a_name() -> None:
    with pytest.raises(BookError, match="share a name"):
        NdjsonBook("pkg", [_WIDGETS, _WIDGETS])


# --------------------------------------------------------------------------- #
# The overwrite guard
# --------------------------------------------------------------------------- #
def test_an_empty_store_may_be_seeded() -> None:
    assert may_overwrite({"a": 0, "b": 0}, []) is True


def test_a_populated_store_without_a_fictional_manifest_is_refused() -> None:
    """The case that matters: a demo loader pointed at somebody's real book."""
    assert may_overwrite({"a": 12}, []) is False
    assert may_overwrite({"a": 12}, [{"fictional": False}]) is False


def test_a_populated_store_that_declares_itself_fictional_may_be_replaced() -> None:
    assert may_overwrite({"a": 12}, [{"fictional": True}]) is True


# --------------------------------------------------------------------------- #
# The tenant rule
# --------------------------------------------------------------------------- #
def test_every_row_carrying_a_tenant_gets_the_deployment_s_own(book: NdjsonBook) -> None:
    stamped = retenant(book.rows("widgets"), "bank.example")
    assert [row["tenant"] for row in stamped] == ["bank.example", "bank.example"]


def test_the_cross_tenant_proof_row_is_kept_separate(book: NdjsonBook) -> None:
    """Folding it in would delete the only evidence the tenant gate does anything."""
    stamped = retenant(book.rows("widgets"), "bank.example", keep_separate={"w-2": "-other"})
    assert [row["tenant"] for row in stamped] == ["bank.example", "bank.example-other"]


def test_a_blank_tenant_is_refused_rather_than_defaulted(book: NdjsonBook) -> None:
    """Rows under no tenant are unreachable, and unreachable reads as empty."""
    with pytest.raises(BookError, match="tenant is required"):
        retenant(book.rows("widgets"), "   ")


def test_rows_without_a_tenant_column_pass_through_untouched() -> None:
    assert retenant([{"id": "x"}], "bank.example") == [{"id": "x"}]


# --------------------------------------------------------------------------- #
# The local store
# --------------------------------------------------------------------------- #
def test_the_store_self_seeds_and_serves_the_book(book: NdjsonBook) -> None:
    store = DuckDbStore(book, ":memory:")
    assert store.row_counts() == {"widgets": 2, "book_manifest": 1}
    rows = store.connection.execute("SELECT widget_id, made_on FROM widgets ORDER BY 1").fetchall()
    assert rows[0][0] == "w-1"
    assert rows[0][1] == date(2026, 1, 2), "a date column must arrive as a date, not a string"
    assert rows[1][1] is None
    store.close()


def test_a_populated_store_is_left_alone_on_reopen(book: NdjsonBook, tmp_path: Path) -> None:
    """Re-seeding on every open would discard what an audience registered earlier."""
    path = str(tmp_path / "book.duckdb")
    first = DuckDbStore(book, path)
    first.connection.execute("INSERT INTO widgets VALUES ('w-9', 'Registered', 'demo-bank', NULL)")
    first.close()

    second = DuckDbStore(book, path)
    assert second.row_counts()["widgets"] == 3, "the reopen discarded a registered row"
    second.close()


def test_an_explicit_reseed_refuses_a_store_that_never_called_itself_fictional(
    book: NdjsonBook, tmp_path: Path
) -> None:
    path = str(tmp_path / "real.duckdb")
    store = DuckDbStore(book, path)
    store.connection.execute("DELETE FROM book_manifest")
    store.connection.execute(
        "INSERT INTO book_manifest VALUES ('bank-v3', DATE '2026-09-01', false, NULL, NULL, 'b')"
    )
    with pytest.raises(PermissionError, match="not say they are fictional"):
        store.seed_shipped_book()
    assert store.row_counts()["widgets"] == 2, "the refusal must leave the rows in place"
    store.close()


def test_the_store_holds_the_columns_in_the_declared_order(book: NdjsonBook) -> None:
    """The property that makes the two stores comparable rather than merely both working."""
    store = DuckDbStore(book, ":memory:")
    columns = [
        row[0]
        for row in store.connection.execute("DESCRIBE widgets").fetchall()  # noqa: PD011
    ]
    assert tuple(columns) == _WIDGETS.columns
    store.close()


def test_as_date_handles_the_three_shapes_a_json_value_arrives_in() -> None:
    assert as_date(None) is None
    assert as_date("") is None
    assert as_date("2026-01-02") == date(2026, 1, 2)
    assert as_date(date(2026, 1, 2)) == date(2026, 1, 2)
