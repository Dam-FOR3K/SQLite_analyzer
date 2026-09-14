"""
Embedded Binary Payload Extractors & Format Decoders.

Automatically identifies, carves, and decodes binary structures inside SQLite BLOBs:
- Apple Binary Plist (`bplist00`)
- Protocol Buffers (Dynamic wire format decoder with strict false-positive filtering)
- Compressed streams (zlib / raw deflate)
"""

from __future__ import annotations

import plistlib
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlite_carver.core.varint import read_varint, safe_read_varint


@dataclass
class DecodedBlobPayload:
    detected_format: str  # 'bplist', 'protobuf', 'zlib', 'png', 'jpeg', 'pdf', 'zip', 'raw'
    confidence: float
    data: Any
    metadata: Dict[str, Any]
    suggested_extension: str = ".bin"
    is_file: bool = False


def decode_bplist(data: bytes) -> Optional[DecodedBlobPayload]:
    """
    Parses Apple Binary Plist (bplist00) data.
    """
    if not data.startswith(b"bplist"):
        return None

    try:
        parsed = plistlib.loads(data)
        # Convert any raw bytes in parsed dict to hex/string for serialization
        def sanitize(obj: Any) -> Any:
            if isinstance(obj, bytes):
                try:
                    return obj.decode("utf-8")
                except UnicodeDecodeError:
                    return obj.hex()
            elif isinstance(obj, dict):
                return {str(k): sanitize(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [sanitize(x) for x in obj]
            return obj

        return DecodedBlobPayload(
            detected_format="bplist",
            confidence=1.0,
            data=sanitize(parsed),
            metadata={"version": data[:8].decode("latin1", errors="replace"), "byte_length": len(data)},
            suggested_extension=".plist",
            is_file=True,
        )
    except Exception:
        return None


def read_leb128(data: bytes | memoryview, offset: int = 0) -> Optional[Tuple[int, int]]:
    """
    Decodes a standard LEB128 unsigned varint used by Protocol Buffers.
    Returns (value, bytes_consumed) or None.
    """
    data_len = len(data)
    if offset >= data_len:
        return None
    val = 0
    shift = 0
    for i in range(10):
        idx = offset + i
        if idx >= data_len:
            return None
        b = data[idx]
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i + 1
        shift += 7
    return None


def decode_protobuf_wire(data: bytes | memoryview, max_depth: int = 4) -> Optional[Dict[str, Any]]:
    """
    Dynamically decodes Protocol Buffers binary wire format without .proto schemas.
    Includes strict structural checks to prevent false positives on random binary data.
    Supports wire types: 0 (Varint), 1 (64-bit), 2 (Length-delimited), 5 (32-bit).
    """
    data_len = len(data)
    if data_len < 2:
        return None

    if max_depth <= 0:
        return {"_truncated_depth": True, "_raw_hex": bytes(data).hex()}

    offset = 0
    fields: Dict[str, Any] = {}
    valid_fields = 0
    structured_evidence = 0

    while offset < data_len:
        tag_res = read_leb128(data, offset)
        if tag_res is None:
            break
        tag_raw, tag_len = tag_res
        offset += tag_len

        field_num = tag_raw >> 3
        wire_type = tag_raw & 0x07

        # Strict protobuf field number validation (1 to 100,000; 19000-19999 reserved)
        if field_num == 0 or field_num > 100000 or (19000 <= field_num <= 19999):
            return None

        field_key = f"field_{field_num}"

        if wire_type == 0:
            # Varint
            v_res = read_leb128(data, offset)
            if v_res is None:
                return None
            val, v_len = v_res
            offset += v_len
            fields.setdefault(field_key, []).append(val)
            valid_fields += 1

        elif wire_type == 1:
            # 64-bit fixed
            if offset + 8 > data_len:
                return None
            raw_64 = data[offset : offset + 8]
            offset += 8
            u_val = struct.unpack("<Q", raw_64)[0]
            f_val = struct.unpack("<d", raw_64)[0]
            fields.setdefault(field_key, []).append(
                {"uint64": u_val, "double": f_val} if abs(f_val) < 1e15 else u_val
            )
            valid_fields += 1

        elif wire_type == 2:
            # Length-delimited (string, bytes, submessage)
            len_res = read_leb128(data, offset)
            if len_res is None:
                return None
            sub_len, l_len = len_res
            offset += l_len

            if offset + sub_len > data_len or sub_len < 0:
                return None

            sub_bytes = bytes(data[offset : offset + sub_len])
            offset += sub_len

            # Try parsing recursively as sub-message
            sub_msg = decode_protobuf_wire(sub_bytes, max_depth=max_depth - 1) if sub_len >= 2 else None
            if sub_msg is not None and len(sub_msg) > 0 and "_truncated_depth" not in sub_msg:
                fields.setdefault(field_key, []).append(sub_msg)
                structured_evidence += 2
            else:
                # Try UTF-8 string
                try:
                    text_val = sub_bytes.decode("utf-8")
                    if all(c.isprintable() or c in "\r\n\t" for c in text_val) and len(text_val) > 0:
                        fields.setdefault(field_key, []).append(text_val)
                        structured_evidence += 1
                    else:
                        fields.setdefault(field_key, []).append(sub_bytes.hex())
                except UnicodeDecodeError:
                    fields.setdefault(field_key, []).append(sub_bytes.hex())
            valid_fields += 1

        elif wire_type == 5:
            # 32-bit fixed
            if offset + 4 > data_len:
                return None
            raw_32 = data[offset : offset + 4]
            offset += 4
            u_val = struct.unpack("<I", raw_32)[0]
            f_val = struct.unpack("<f", raw_32)[0]
            fields.setdefault(field_key, []).append(
                {"uint32": u_val, "float": f_val} if abs(f_val) < 1e10 else u_val
            )
            valid_fields += 1

        else:
            # Unsupported / invalid wire type (e.g. 3, 4 deprecated groups or invalid 6, 7)
            return None

    # Strict acceptance: 100% of data bytes must be consumed with at least 1 valid field
    if valid_fields > 0 and offset == data_len:
        # Simplify single-item lists
        simplified = {}
        for k, v in fields.items():
            simplified[k] = v[0] if len(v) == 1 else v
        return simplified

    return None


def decode_zlib(data: bytes) -> Optional[DecodedBlobPayload]:
    """
    Decompresses zlib/deflate streams and inspects decompressed content.
    """
    if len(data) < 6:
        return None

    # Check for zlib header signatures: 0x78 0x01, 0x78 0x9c, 0x78 0xda, 0x78 0x5e
    is_zlib = (data[0] == 0x78 and data[1] in (0x01, 0x9C, 0xDA, 0x5E))
    try:
        if is_zlib:
            decomp = zlib.decompress(data)
        else:
            # Try raw deflate
            decomp = zlib.decompress(data, -zlib.MAX_WBITS)

        # Attempt to decode decompressed data as plist, protobuf, or text
        sub_plist = decode_bplist(decomp)
        if sub_plist:
            return DecodedBlobPayload(
                detected_format="zlib+bplist",
                confidence=1.0,
                data=sub_plist.data,
                metadata={"compressed_size": len(data), "uncompressed_size": len(decomp)},
            )

        sub_proto = decode_protobuf_wire(decomp)
        if sub_proto and len(sub_proto) >= 1:
            return DecodedBlobPayload(
                detected_format="zlib+protobuf",
                confidence=0.85,
                data=sub_proto,
                metadata={"compressed_size": len(data), "uncompressed_size": len(decomp)},
            )

        try:
            text = decomp.decode("utf-8")
            if all(c.isprintable() or c in "\r\n\t" for c in text):
                return DecodedBlobPayload(
                    detected_format="zlib+text",
                    confidence=0.95,
                    data=text,
                    metadata={"compressed_size": len(data), "uncompressed_size": len(decomp)},
                )
        except UnicodeDecodeError:
            pass

        return DecodedBlobPayload(
            detected_format="zlib+binary",
            confidence=0.85,
            data=decomp.hex(),
            metadata={"compressed_size": len(data), "uncompressed_size": len(decomp)},
        )

    except Exception:
        return None


def detect_file_signature(data: bytes) -> Optional[Tuple[str, str, str]]:
    """
    Checks common binary file signatures.
    Returns (format_name, extension, mime_type) or None.
    """
    if len(data) < 4:
        return None

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", ".png", "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg", ".jpg", "image/jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif", ".gif", "image/gif"
    if data.startswith(b"%PDF-"):
        return "pdf", ".pdf", "application/pdf"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "zip", ".zip", "application/zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip", ".gz", "application/gzip"
    if data.startswith(b"SQLite format 3\x00"):
        return "sqlite", ".sqlite", "application/x-sqlite3"
    if data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):
        return "tiff", ".tiff", "image/tiff"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "webp", ".webp", "image/webp"

    return None


def dump_blob_to_file(data: bytes, target_path: str | Path, ensure_extension: bool = True) -> Path:
    """
    Dumps raw BLOB data to a file. If ensure_extension is True, automatically appends
    the detected file extension (e.g. .jpg, .png, .pdf, .plist, .bin) if not already present.
    """
    p = Path(target_path)
    if ensure_extension and not p.suffix:
        info = inspect_blob(data)
        ext = info.suggested_extension or ".bin"
        p = p.with_suffix(ext)

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def inspect_blob(data: bytes) -> DecodedBlobPayload:
    """
    Analyzes any binary BLOB and runs automated format extractors with calibrated confidence.
    Supports file signatures (JPEG, PNG, GIF, PDF, ZIP, WebP), Apple bplist, Zlib, Protobuf, and UTF-8.
    """
    if not data:
        return DecodedBlobPayload("raw", 1.0, "", {"size": 0}, suggested_extension=".bin")

    # 1. Try Apple Binary Plist (Magic Header: bplist00 -> 100% confidence)
    bplist_res = decode_bplist(data)
    if bplist_res:
        return bplist_res

    # 2. Try Known File Magic Signatures (JPEG, PNG, GIF, PDF, ZIP, GZIP, WebP, SQLite)
    file_sig = detect_file_signature(data)
    if file_sig:
        fmt, ext, mime = file_sig
        return DecodedBlobPayload(
            detected_format=fmt,
            confidence=1.0,
            data=f"<{fmt.upper()} {len(data)} bytes>",
            metadata={"mime_type": mime, "byte_length": len(data), "suggested_extension": ext},
            suggested_extension=ext,
            is_file=True,
        )

    # 3. Try Zlib Compression (CRC & Adler32 check -> 85-95% confidence)
    zlib_res = decode_zlib(data)
    if zlib_res:
        return zlib_res

    # 4. Try Protocol Buffers (Dynamic scoring to avoid false positives on random bytes)
    proto_res = decode_protobuf_wire(data)
    if proto_res and len(proto_res) > 0:
        field_count = len(proto_res)
        conf = 0.85 if field_count >= 2 else 0.65
        return DecodedBlobPayload(
            detected_format="protobuf",
            confidence=conf,
            data=proto_res,
            metadata={"byte_length": len(data), "field_count": field_count},
            suggested_extension=".bin",
        )

    # 5. Fallback to raw utf-8 text representation if 100% printable
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text) and len(text) > 0:
            return DecodedBlobPayload("text", 1.0, text, {"size": len(data)}, suggested_extension=".txt")
    except UnicodeDecodeError:
        pass

    return DecodedBlobPayload("raw_hex", 1.0, data.hex(), {"size": len(data)}, suggested_extension=".bin")

