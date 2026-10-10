import math
import struct

from src.ml.feature_extractor import FeatureExtractor


def tiny_pe() -> bytes:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = 0x178
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200:] = bytes(range(256)) * 2
    return bytes(data)


def test_tiny_pe_returns_fixed_order_finite_feature_vector() -> None:
    extractor = FeatureExtractor()
    features = extractor.extract(tiny_pe())
    names = extractor.get_feature_names()
    assert len(names) == 77
    assert list(features) == names
    assert len(features) == 77
    assert all(math.isfinite(value) for value in features.values())
    assert features["machine"] == 0x14C
    assert features["number_of_sections"] == 1


def test_malformed_pe_degrades_without_raising() -> None:
    features = FeatureExtractor().extract(b"MZ" + b"not-a-valid-pe")
    assert len(features) == 77
    assert all(math.isfinite(value) for value in features.values())
