"""
sqlite_carver.decoders.geolocation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Forensic geolocation and coordinate pair detection engine.
Identifies latitude, longitude, altitude, and generates interactive OpenStreetMap links.
Prioritizes column names matching latitude / longitude patterns to avoid false positives.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DecodedCoordinate:
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    lat_col: Optional[str] = None
    lon_col: Optional[str] = None
    open_street_map_url: str = ""

    def __post_init__(self):
        if not self.open_street_map_url:
            self.open_street_map_url = (
                f"https://www.openstreetmap.org/?mlat={self.latitude:.6f}&mlon={self.longitude:.6f}#map=16/{self.latitude:.6f}/{self.longitude:.6f}"
            )


EXCLUDE_LAT = (
    "plate", "late", "flat", "slat", "splat", "plat", "isolate", "calculate",
    "translate", "collate", "inflate", "relate", "chocolate", "accumulate",
    "relative", "template", "collateral", "lateral", "translated"
)

EXCLUDE_LON = (
    "belong", "prolong", "along", "furlong", "headlong", "nightlong", "lifelong",
    "long_text", "long_desc", "long_string", "long_blob", "long_data"
)

SINGLE_COORD_COLS = {
    "coordinates", "coordinate", "coords", "coord", "location", "position",
    "geo_point", "gps_point", "geolocation", "lat_lon", "latlon", "lat_long",
    "latlong", "geopoint", "gpspoint", "geom", "geometry"
}


def normalize_name(name: str) -> str:
    """Converts column names to normalized snake_case."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name.strip())
    s = re.sub(r"[^a-zA-Z0-9_]+", "_", s).lower()
    return s.strip("_")


def is_lat_column(col_name: str) -> bool:
    """Checks if a column name represents Latitude."""
    norm = normalize_name(col_name)
    if "latitude" in norm:
        return not any(norm.endswith(ex) for ex in EXCLUDE_LAT)
    tokens = norm.split("_")
    lat_tokens = {"lat", "clat", "ylat", "geolat", "gpslat"}
    if any(t in lat_tokens or (t.startswith("lat") and t[3:].isdigit()) for t in tokens):
        return not any(norm.endswith(ex) for ex in EXCLUDE_LAT)
    if norm.endswith("lat") or norm.startswith("lat_"):
        return not any(norm.endswith(ex) for ex in EXCLUDE_LAT)
    return False


def is_lon_column(col_name: str) -> bool:
    """Checks if a column name represents Longitude."""
    norm = normalize_name(col_name)
    if "longitude" in norm:
        return not any(norm.endswith(ex) for ex in EXCLUDE_LON)
    tokens = norm.split("_")
    lon_tokens = {"lon", "lng", "long", "clon", "clng", "xlon", "geolon", "gpslon", "gpslng"}
    if any(t in lon_tokens or (t.startswith(("lon", "lng")) and t[3:].isdigit()) for t in tokens):
        return not any(norm.endswith(ex) for ex in EXCLUDE_LON)
    if norm.endswith(("lon", "lng")) or norm.startswith(("lon_", "lng_")):
        return not any(norm.endswith(ex) for ex in EXCLUDE_LON)
    return False


def is_alt_column(col_name: str) -> bool:
    """Checks if a column name represents Altitude or Elevation."""
    norm = normalize_name(col_name)
    if "altitude" in norm or "elevation" in norm:
        return True
    tokens = norm.split("_")
    return any(t in {"alt", "calt", "elev", "geoalt", "gpsalt"} for t in tokens)


def is_single_coord_column(col_name: str) -> bool:
    """Checks if a single column name indicates combined coordinates."""
    norm = normalize_name(col_name)
    if norm in SINGLE_COORD_COLS:
        return True
    tokens = set(norm.split("_"))
    return bool(tokens & {"coord", "coords", "coordinates", "location", "position", "geolocation", "latlon", "geopoint", "gpspoint"})


def is_valid_latitude(val: float) -> bool:
    return -90.0 <= val <= 90.0 and abs(val) > 0.0001


def is_valid_longitude(val: float) -> bool:
    return -180.0 <= val <= 180.0 and abs(val) > 0.0001


def normalize_coord_val(val: Any) -> Optional[float]:
    """Converts int (microdegrees) or float/string to standard decimal degrees."""
    if val is None:
        return None
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        f = float(val)
        if abs(f) > 180.0:
            if abs(f) <= 180_000_000.0:
                f = f / 1_000_000.0
            elif abs(f) <= 1_800_000_000.0:
                f = f / 10_000_000.0
        return f
    if isinstance(val, str):
        val_clean = val.strip()
        try:
            f = float(val_clean)
            if abs(f) > 180.0:
                if abs(f) <= 180_000_000.0:
                    f = f / 1_000_000.0
                elif abs(f) <= 1_800_000_000.0:
                    f = f / 10_000_000.0
            return f
        except ValueError:
            pass
    return None


def parse_single_coord_val(val: Any) -> Optional[Tuple[float, float]]:
    """Parses a combined coordinate string or dictionary into (latitude, longitude)."""
    if isinstance(val, dict):
        lat = val.get("lat") or val.get("latitude")
        lon = val.get("lon") or val.get("lng") or val.get("longitude")
        if lat is not None and lon is not None:
            n_lat, n_lon = normalize_coord_val(lat), normalize_coord_val(lon)
            if n_lat is not None and n_lon is not None:
                if is_valid_latitude(n_lat) and is_valid_longitude(n_lon):
                    return n_lat, n_lon

    if isinstance(val, str):
        s = val.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                d = json.loads(s)
                return parse_single_coord_val(d)
            except Exception:
                pass

        # WKT: POINT(lon lat)
        m_point = re.match(r"POINT\s*\(\s*([-\d\.]+)\s+([-\d\.]+)\s*\)", s, re.IGNORECASE)
        if m_point:
            lon, lat = float(m_point.group(1)), float(m_point.group(2))
            if is_valid_latitude(lat) and is_valid_longitude(lon):
                return lat, lon

        # geo: URI e.g. geo:48.858844,2.294351
        if s.lower().startswith("geo:"):
            s = s[4:].split(";")[0].split("?")[0]

        # Standard 'lat, lon' or 'lat; lon'
        s_clean = s.strip("()[]{}")
        parts = re.split(r"[,;\s]+", s_clean)
        if len(parts) >= 2:
            try:
                lat = float(parts[0])
                lon = float(parts[1])
                if is_valid_latitude(lat) and is_valid_longitude(lon):
                    return lat, lon
            except ValueError:
                pass
    return None


def get_lat_stem(name: str) -> str:
    norm = normalize_name(name)
    return re.sub(r"lat(?:itude)?", "", norm).strip("_")


def get_lon_stem(name: str) -> str:
    norm = normalize_name(name)
    return re.sub(r"(?:longitude|long|lon|lng)", "", norm).strip("_")


def extract_coordinates(
    columns: Dict[str, Any] | List[Tuple[str, Any]]
) -> Optional[DecodedCoordinate]:
    """
    Extracts a valid geographic coordinate pair from a row dictionary or column-value list.
    Only extracts coordinates when column names indicate latitude/longitude or location.
    """
    if isinstance(columns, dict):
        items = list(columns.items())
    else:
        items = columns

    # 1. Check for single-column coordinate values
    for col_name, val in items:
        if is_single_coord_column(col_name) or (isinstance(val, str) and (val.startswith("geo:") or val.upper().startswith("POINT("))):
            coords = parse_single_coord_val(val)
            if coords:
                lat, lon = coords
                return DecodedCoordinate(
                    latitude=round(lat, 6),
                    longitude=round(lon, 6),
                    lat_col=col_name,
                    lon_col=col_name,
                )

    # 2. Check for lat / lon column pairs
    candidate_lats: List[Tuple[str, float]] = []
    candidate_lons: List[Tuple[str, float]] = []
    alt_val: Optional[float] = None

    for col_name, val in items:
        c_val = normalize_coord_val(val)
        if c_val is not None:
            if is_lat_column(col_name) and is_valid_latitude(c_val):
                candidate_lats.append((col_name, c_val))
            elif is_lon_column(col_name) and is_valid_longitude(c_val):
                candidate_lons.append((col_name, c_val))
            elif is_alt_column(col_name) and alt_val is None:
                alt_val = c_val

    if candidate_lats and candidate_lons:
        best_lat_col, best_lat = candidate_lats[0]
        best_lon_col, best_lon = candidate_lons[0]

        # If multiple candidates, try to match by column stem (e.g. pickup_lat / pickup_lon)
        if len(candidate_lats) > 1 or len(candidate_lons) > 1:
            for l_col, l_val in candidate_lats:
                l_stem = get_lat_stem(l_col)
                for o_col, o_val in candidate_lons:
                    o_stem = get_lon_stem(o_col)
                    if l_stem == o_stem:
                        best_lat_col, best_lat = l_col, l_val
                        best_lon_col, best_lon = o_col, o_val
                        break

        return DecodedCoordinate(
            latitude=round(best_lat, 6),
            longitude=round(best_lon, 6),
            altitude=round(alt_val, 2) if alt_val is not None else None,
            lat_col=best_lat_col,
            lon_col=best_lon_col,
        )

    return None
