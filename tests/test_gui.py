import pytest
from sqlite_carver.core.carver import CarvedRecord
from sqlite_carver.gui.app import SQLiteCarverApp, HexInspectorModal


def test_gui_initialization_and_search_filter():
    try:
        app = SQLiteCarverApp()
    except Exception as e:
        pytest.skip(f"GUI display not available or Tkinter initialization skipped: {e}")

    app.withdraw()

    try:
        r1 = CarvedRecord(
            page_id=2,
            offset_in_page=100,
            source="active",
            confidence=1.0,
            matched_table="users",
            rowid=1,
            column_names=["id", "username"],
            column_types=["INTEGER", "TEXT"],
            values=[1, "alice"],
            serial_types=[1, 23],
            raw_payload=b"user_alice_payload",
        )
        r2 = CarvedRecord(
            page_id=2,
            offset_in_page=200,
            source="freeblock",
            confidence=0.88,
            matched_table="messages",
            rowid=2,
            column_names=["id", "text"],
            column_types=["INTEGER", "TEXT"],
            values=[2, "classified intelligence"],
            serial_types=[1, 33],
            raw_payload=b"classified intelligence",
        )

        app.all_evidence = [r1, r2]
        app._populate_tree(app.all_evidence)

        # Filter by table
        app.table_filter.set("messages")
        app._apply_filters()
        assert len(app.filtered_evidence) == 1
        assert app.filtered_evidence[0].matched_table == "messages"

        # Filter by search text
        app.table_filter.set("All Tables")
        app.search_entry.delete(0, "end")
        app.search_entry.insert(0, "alice")
        app._apply_filters()
        assert len(app.filtered_evidence) == 1
        assert app.filtered_evidence[0].matched_table == "users"

        modal = HexInspectorModal(app, r1, "Test Modal")
        modal.withdraw()
        assert "alice" in modal.text_box.get("1.0", "end")
        modal.destroy()

    finally:
        app.destroy()
