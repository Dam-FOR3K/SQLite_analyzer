import pytest
from sqlite_carver.core.carver import CarvedRecord
from sqlite_carver.exporters.export import record_to_dict
from sqlite_carver.exporters.html_report import generate_html_report


def test_record_to_dict_includes_raw_payload_hex():
    rec = CarvedRecord(
        page_id=2,
        offset_in_page=128,
        source="freeblock",
        confidence=0.88,
        matched_table="users",
        rowid=42,
        column_names=["id", "name"],
        column_types=["INTEGER", "TEXT"],
        values=[42, "Alice"],
        serial_types=[1, 23],
        raw_payload=b"\x01\x17Alice",
    )

    d = record_to_dict(rec)
    assert "raw_payload_hex" in d
    assert d["raw_payload_hex"] == "0117416c696365"
    assert d["source"] == "freeblock"
    assert d["rowid"] == 42


def test_html_report_contains_hex_inspector_modal(tmp_path):
    rec = CarvedRecord(
        page_id=3,
        offset_in_page=256,
        source="slack",
        confidence=0.75,
        matched_table="messages",
        rowid=101,
        column_names=["id", "text"],
        column_types=["INTEGER", "TEXT"],
        values=[101, "TopSecretPayload"],
        serial_types=[1, 33],
        raw_payload=b"TopSecretPayload\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    )

    out_file = tmp_path / "report.html"
    generate_html_report(
        records=[rec],
        output_path=out_file,
        title="Forensic Test Report",
        lang="en",
    )
    html_content = out_file.read_text(encoding="utf-8")

    # Verify modal HTML structure
    assert 'id="hexModal"' in html_content
    assert "Hex & ASCII Payload Inspector" in html_content
    assert 'id="hexViewerContainer"' in html_content

    # Verify interactive modal buttons
    assert "Copy Hex" in html_content
    assert "Copy ASCII" in html_content
    assert "Download .bin" in html_content

    # Verify JavaScript handler functions
    assert "function openHexModal(" in html_content
    assert "function closeHexModal()" in html_content
    assert "function copyHexPayload()" in html_content
    assert "function copyAsciiPayload()" in html_content
    assert "function downloadHexBinary()" in html_content

    # Verify table row contains Hex inspect button
    assert "openHexModal(" in html_content
    assert "🔍 Hex" in html_content
