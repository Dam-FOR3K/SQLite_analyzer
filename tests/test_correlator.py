import pytest
from sqlite_carver.core.carver import CarvedRecord, TableSchema
from sqlite_carver.core.correlator import EntityCorrelator, FKLink


def test_fk_discovery_explicit_and_heuristic():
    user_schema = TableSchema.from_sql("users", 2, "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    order_schema = TableSchema.from_sql(
        "orders",
        3,
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL, FOREIGN KEY (user_id) REFERENCES users(id))"
    )
    item_schema = TableSchema.from_sql(
        "order_items",
        4,
        "CREATE TABLE order_items (item_id INTEGER PRIMARY KEY, order_id INTEGER, product_name TEXT)"
    )

    schemas = {
        "users": user_schema,
        "orders": order_schema,
        "order_items": item_schema,
    }

    correlator = EntityCorrelator(schemas)
    links = correlator.fk_links

    # Check that orders -> users is found (explicit)
    order_user_link = next((l for l in links if l.source_table == "orders" and l.source_column == "user_id"), None)
    assert order_user_link is not None
    assert order_user_link.target_table == "users"

    # Check that order_items -> orders is found (heuristic by convention)
    item_order_link = next((l for l in links if l.source_table == "order_items" and l.source_column == "order_id"), None)
    assert item_order_link is not None
    assert item_order_link.target_table == "orders"


def test_correlate_records():
    user_schema = TableSchema.from_sql("users", 2, "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    msg_schema = TableSchema.from_sql(
        "messages",
        3,
        "CREATE TABLE messages (id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT, FOREIGN KEY (user_id) REFERENCES users(id))"
    )

    schemas = {"users": user_schema, "messages": msg_schema}
    correlator = EntityCorrelator(schemas)

    user_rec = CarvedRecord(
        page_id=2,
        offset_in_page=100,
        source="active",
        confidence=1.0,
        matched_table="users",
        rowid=42,
        values=[42, "Alice"],
        column_names=["id", "username"],
        column_types=["INTEGER", "TEXT"],
        serial_types=[1, 19],
        raw_payload=b"",
    )

    msg_rec = CarvedRecord(
        page_id=3,
        offset_in_page=200,
        source="active",
        confidence=1.0,
        matched_table="messages",
        rowid=1,
        values=[1, 42, "Hello world"],
        column_names=["id", "user_id", "body"],
        column_types=["INTEGER", "INTEGER", "TEXT"],
        serial_types=[1, 1, 31],
        raw_payload=b"",
    )

    records = [user_rec, msg_rec]
    correlator.correlate_records(records)

    assert "user_id" in msg_rec.foreign_keys
    fk_info = msg_rec.foreign_keys["user_id"]
    assert fk_info["target_table"] == "users"
    assert fk_info["target_id"] == 42
    assert fk_info["display_value"] == "Alice"
