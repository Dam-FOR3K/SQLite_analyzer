import pytest
from sqlite_carver.decoders.geolocation import (
    DecodedCoordinate,
    extract_coordinates,
    is_lat_column,
    is_lon_column,
    is_valid_latitude,
    is_valid_longitude,
    normalize_coord_val,
)


def test_lat_lon_validation():
    assert is_valid_latitude(48.858844) is True
    assert is_valid_latitude(-33.8688) is True
    assert is_valid_latitude(95.0) is False
    assert is_valid_latitude(0.0) is False

    assert is_valid_longitude(2.294351) is True
    assert is_valid_longitude(-151.2093) is True
    assert is_valid_longitude(190.0) is False


def test_normalize_microdegrees():
    # Microdegrees format e.g. 48858844 -> 48.858844
    norm = normalize_coord_val(48858844)
    assert norm is not None
    assert round(norm, 6) == 48.858844

    norm2 = normalize_coord_val(-122419416)
    assert norm2 is not None
    assert round(norm2, 6) == -122.419416

    # 1e7 microdegrees format e.g. 488588440 -> 48.858844
    norm3 = normalize_coord_val(488588440)
    assert norm3 is not None
    assert round(norm3, 6) == 48.858844


def test_column_name_detection():
    # Valid lat column names
    assert is_lat_column("lat") is True
    assert is_lat_column("latitude") is True
    assert is_lat_column("user_lat") is True
    assert is_lat_column("userLat") is True
    assert is_lat_column("gps_latitude") is True
    assert is_lat_column("start_lat_deg") is True
    assert is_lat_column("devicelat") is True

    # Excluded lat terms (false positive avoidance)
    assert is_lat_column("license_plate") is False
    assert is_lat_column("late_fee") is False
    assert is_lat_column("template_name") is False
    assert is_lat_column("relative_path") is False

    # Valid lon column names
    assert is_lon_column("lon") is True
    assert is_lon_column("lng") is True
    assert is_lon_column("long") is True
    assert is_lon_column("longitude") is True
    assert is_lon_column("user_lng") is True
    assert is_lon_column("userLon") is True
    assert is_lon_column("gps_longitude") is True
    assert is_lon_column("devicelon") is True

    # Excluded lon terms
    assert is_lon_column("belong") is False
    assert is_lon_column("prolong") is False
    assert is_lon_column("long_text") is False


def test_extract_coordinates_from_columns():
    row_data = {
        "message_id": 1024,
        "latitude": 48.858844,
        "longitude": 2.294351,
        "altitude": 35.5,
        "text": "Meeting here",
    }
    coord = extract_coordinates(row_data)
    assert coord is not None
    assert coord.latitude == 48.858844
    assert coord.longitude == 2.294351
    assert coord.altitude == 35.5
    assert "openstreetmap.org" in coord.open_street_map_url
    assert "mlat=48.858844" in coord.open_street_map_url


def test_extract_coordinates_microdegrees_row():
    row_data = {
        "id": 42,
        "lat": 37774929,
        "lon": -122419416,
    }
    coord = extract_coordinates(row_data)
    assert coord is not None
    assert round(coord.latitude, 4) == 37.7749
    assert round(coord.longitude, 4) == -122.4194


def test_extract_coordinates_camelcase_and_variations():
    row_data = {
        "user_id": 99,
        "userLat": 48.858844,
        "userLng": 2.294351,
    }
    coord = extract_coordinates(row_data)
    assert coord is not None
    assert coord.latitude == 48.858844
    assert coord.longitude == 2.294351
    assert coord.lat_col == "userLat"
    assert coord.lon_col == "userLng"


def test_extract_coordinates_single_column_strings():
    # Comma separated
    c1 = extract_coordinates({"id": 1, "coordinates": "48.858844, 2.294351"})
    assert c1 is not None
    assert c1.latitude == 48.858844
    assert c1.longitude == 2.294351

    # WKT POINT(lon lat)
    c2 = extract_coordinates({"id": 2, "location": "POINT(2.294351 48.858844)"})
    assert c2 is not None
    assert c2.latitude == 48.858844
    assert c2.longitude == 2.294351

    # geo: URI
    c3 = extract_coordinates({"id": 3, "position": "geo:48.858844,2.294351"})
    assert c3 is not None
    assert c3.latitude == 48.858844
    assert c3.longitude == 2.294351


def test_no_false_positives_on_adjacent_numbers():
    # Previous bug: random adjacent numeric fields were flagged as GPS points
    row_data = {
        "product_id": 100,
        "price": 19.99,
        "tax": 5.0,
        "discount": 2.5,
    }
    assert extract_coordinates(row_data) is None

    row_data2 = {
        "shape_id": 5,
        "width": 80.0,
        "height": 40.0,
    }
    assert extract_coordinates(row_data2) is None

    row_data3 = {
        "point_id": 12,
        "x": 10.0,
        "y": 20.0,
    }
    assert extract_coordinates(row_data3) is None


def test_paired_stem_matching():
    # When multiple lat/lon exist in same row, paired by stem
    row_data = {
        "trip_id": 1234,
        "pickup_lat": 48.858844,
        "pickup_lon": 2.294351,
        "dropoff_latitude": 48.860000,
        "dropoff_longitude": 2.300000,
    }
    coord = extract_coordinates(row_data)
    assert coord is not None
    assert (coord.lat_col == "pickup_lat" and coord.lon_col == "pickup_lon") or \
           (coord.lat_col == "dropoff_latitude" and coord.lon_col == "dropoff_longitude")
