import tempfile
from pathlib import Path
from sqlite_carver.decoders.blobs import (
    detect_file_signature,
    dump_blob_to_file,
    inspect_blob,
)

def test_detect_image_signatures():
    # PNG
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    sig = detect_file_signature(png_header)
    assert sig is not None
    assert sig[0] == "png"
    assert sig[1] == ".png"

    # JPEG
    jpeg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    sig = detect_file_signature(jpeg_header)
    assert sig is not None
    assert sig[0] == "jpeg"
    assert sig[1] == ".jpg"

    # PDF
    pdf_header = b"%PDF-1.5 test document"
    sig = detect_file_signature(pdf_header)
    assert sig is not None
    assert sig[0] == "pdf"
    assert sig[1] == ".pdf"

    # ZIP
    zip_header = b"PK\x03\x04\x14\x00"
    sig = detect_file_signature(zip_header)
    assert sig is not None
    assert sig[0] == "zip"
    assert sig[1] == ".zip"

def test_inspect_blob_file_types():
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    info = inspect_blob(png_data)
    assert info.detected_format == "png"
    assert info.suggested_extension == ".png"
    assert info.is_file is True

def test_dump_blob_to_file():
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "evidence_image"
        saved_path = dump_blob_to_file(png_data, target)
        assert saved_path.suffix == ".png"
        assert saved_path.exists()
        assert saved_path.read_bytes() == png_data
