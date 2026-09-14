"""
Multi-Format Forensic Timestamp Decoder.

Automatically identifies, converts, and formats numeric timestamps common in
digital forensic investigations across iOS, Android, macOS, Windows, and browsers:
- Unix Epoch (seconds, milliseconds, microseconds, nanoseconds)
- WebKit / Chrome / Safari timestamp (microseconds since 1601-01-01)
- Windows FILETIME (100-nanosecond intervals since 1601-01-01)
- Mac / Cocoa Absolute Time (seconds / nanoseconds since 2001-01-01)
- GPS Time (seconds since 1980-01-06)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional

# Epoch offsets relative to Unix Epoch (1970-01-01 00:00:00 UTC)
WINDOWS_EPOCH_DIFF_SEC = 11644473600  # Between 1601-01-01 and 1970-01-01
COCOA_EPOCH_DIFF_SEC = 978307200      # Between 1970-01-01 and 2001-01-01
GPS_EPOCH_DIFF_SEC = 315964800        # Between 1970-01-01 and 1980-01-06

# Sensible date window for forensic artifacts: 1990 to 2045
MIN_VALID_UNIX_SEC = 631152000    # 1990-01-01
MAX_VALID_UNIX_SEC = 2366841600   # 2045-01-01


@dataclass
class DecodedTimestamp:
    format_name: str       # 'webkit', 'filetime', 'unix_ms', 'unix_sec', 'cocoa_sec', 'gps'
    iso_utc: str           # '2024-08-24 11:46:40 UTC'
    epoch_value: int | float
    confidence: float      # 0.0 - 1.0
    description: str

    def to_display_string(self) -> str:
        return f"{self.iso_utc} [{self.description}]"


def _format_utc(unix_sec: float) -> Optional[str]:
    """Converts a unix timestamp in seconds to ISO UTC string if in valid range."""
    if not (MIN_VALID_UNIX_SEC <= unix_sec <= MAX_VALID_UNIX_SEC):
        return None
    try:
        dt = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError):
        return None


def decode_timestamp(value: Any, column_hint: str = "") -> Optional[DecodedTimestamp]:
    """
    Intelligently determines if a numeric value is a forensic timestamp and decodes it.
    Uses value range analysis and column name semantics to disambiguate.
    """
    if not isinstance(value, (int, float)):
        return None

    # Skip zero or negative values
    if value <= 0:
        return None

    col_lower = column_hint.lower() if column_hint else ""
    is_date_col = bool(re.search(r"(time|date|created|modified|updated|sent|recv|last|ts|expire|stamp|seen)", col_lower))

    # 1. Windows FILETIME (100-nanoseconds since 1601-01-01)
    # Range for 1990-2045: ~ 1.22e17 to 1.40e17
    if 110000000000000000 <= value <= 150000000000000000:
        unix_sec = (value / 10_000_000.0) - WINDOWS_EPOCH_DIFF_SEC
        iso = _format_utc(unix_sec)
        if iso:
            return DecodedTimestamp(
                format_name="filetime",
                iso_utc=iso,
                epoch_value=value,
                confidence=0.98 if is_date_col else 0.90,
                description="Windows FILETIME (100ns)",
            )

    # 2. WebKit / Chrome Microseconds (since 1601-01-01)
    # Range for 1990-2045: ~ 1.22e16 to 1.40e16
    if 11000000000000000 <= value <= 15000000000000000:
        unix_sec = (value / 1_000_000.0) - WINDOWS_EPOCH_DIFF_SEC
        iso = _format_utc(unix_sec)
        if iso:
            return DecodedTimestamp(
                format_name="webkit",
                iso_utc=iso,
                epoch_value=value,
                confidence=0.98 if is_date_col else 0.90,
                description="WebKit / Chrome / Safari (µs)",
            )

    # 3. Unix Microseconds
    # Range: ~ 6.3e14 to 2.36e15
    if 631152000000000 <= value <= 2366841600000000:
        unix_sec = value / 1_000_000.0
        iso = _format_utc(unix_sec)
        if iso:
            return DecodedTimestamp(
                format_name="unix_us",
                iso_utc=iso,
                epoch_value=value,
                confidence=0.95 if is_date_col else 0.85,
                description="Unix Epoch (µs)",
            )

    # 4. Unix Milliseconds (Standard JavaScript / Android / Java timestamps)
    # Range: ~ 6.3e11 to 2.36e12
    if 631152000000 <= value <= 2366841600000:
        unix_sec = value / 1_000.0
        iso = _format_utc(unix_sec)
        if iso:
            return DecodedTimestamp(
                format_name="unix_ms",
                iso_utc=iso,
                epoch_value=value,
                confidence=0.98 if is_date_col else 0.88,
                description="Unix Epoch (ms)",
            )

    # 5. Seconds-based values: Could be Mac/Cocoa Absolute, Unix seconds, or GPS
    # If column hint mentions apple/mac/cocoa/z_pk or iOS CoreData tables (e.g. ZDATE, ZTIMESTAMP)
    is_mac_hint = bool(re.search(r"(mac|cocoa|apple|z_opt|zdate|ztimestamp|coredata)", col_lower))

    # Mac Cocoa Absolute Time (seconds since 2001-01-01)
    # Range: 0 to ~ 1.38e9 (for 2001 to 2045)
    if is_mac_hint and 0 <= value <= 1400000000:
        unix_sec = value + COCOA_EPOCH_DIFF_SEC
        iso = _format_utc(unix_sec)
        if iso:
            return DecodedTimestamp(
                format_name="cocoa_sec",
                iso_utc=iso,
                epoch_value=value,
                confidence=0.95,
                description="Mac / Cocoa Absolute Time (sec)",
            )

    # Unix Epoch in Seconds (e.g. 1724500000)
    if MIN_VALID_UNIX_SEC <= value <= MAX_VALID_UNIX_SEC:
        iso = _format_utc(float(value))
        if iso:
            # If it's a date column or within modern unix bounds (2010-2035)
            is_modern = 1262304000 <= value <= 2051222400
            conf = 0.95 if is_date_col else (0.80 if is_modern else 0.60)
            return DecodedTimestamp(
                format_name="unix_sec",
                iso_utc=iso,
                epoch_value=value,
                confidence=conf,
                description="Unix Epoch (sec)",
            )

    # Non-hinted Cocoa fallback for values between 2001 and 2030 (0 to 9.5e8) when marked as timestamp
    if is_date_col and 0 < value < 950000000:
        unix_sec = value + COCOA_EPOCH_DIFF_SEC
        iso = _format_utc(unix_sec)
        if iso:
            return DecodedTimestamp(
                format_name="cocoa_sec",
                iso_utc=iso,
                epoch_value=value,
                confidence=0.75,
                description="Mac / Cocoa Absolute Time (sec)",
            )

    return None


def get_all_possible_timestamps(value: Any) -> List[DecodedTimestamp]:
    """
    Returns all plausible forensic timestamp interpretations for a numeric value.
    Useful for detailed inspection panels where ambiguous seconds values could be either
    Unix seconds or Cocoa seconds.
    """
    results: List[DecodedTimestamp] = []
    if not isinstance(value, (int, float)) or value <= 0:
        return results

    # Check primary detection
    primary = decode_timestamp(value)
    if primary:
        results.append(primary)

    # If it was decoded as Unix sec, also test Cocoa interpretation
    if MIN_VALID_UNIX_SEC <= value <= MAX_VALID_UNIX_SEC:
        cocoa_sec = value + COCOA_EPOCH_DIFF_SEC
        iso_cocoa = _format_utc(cocoa_sec)
        if iso_cocoa and (not primary or primary.format_name != "cocoa_sec"):
            results.append(
                DecodedTimestamp(
                    format_name="cocoa_sec",
                    iso_utc=iso_cocoa,
                    epoch_value=value,
                    confidence=0.70,
                    description="Mac / Cocoa Absolute Time (sec)",
                )
            )

    return results
