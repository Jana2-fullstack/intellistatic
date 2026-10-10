"""Generate a reproducible synthetic feature dataset for pipeline demonstrations."""
from pathlib import Path
import sys
import json

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from src.ml.feature_extractor import FeatureExtractor  # noqa: E402

SEED = 42
FAMILIES = ["Benign", "Trojan", "Ransomware", "Spyware", "Worm", "Adware"]
COUNTS = {"Benign": 4000, **{family: 800 for family in FAMILIES[1:]}}


def generate_row(rng: np.random.Generator, family: str) -> dict[str, float]:
    malicious = family != "Benign"
    row = {name: 0.0 for name in FeatureExtractor.get_feature_names()}
    row.update({
        "machine": 332 if rng.random() < .92 else 34404,
        "number_of_sections": int(np.clip(rng.normal(5.2 if not malicious else 7.0, 1.7), 1, 18)),
        "time_date_stamp": int(rng.integers(900_000_000, 1_900_000_000)),
        "size_of_optional_header": 224,
        "characteristics": int(rng.integers(2_000, 65_000)),
        "major_linker_version": int(np.clip(rng.normal(10, 4), 2, 15)),
        "size_of_code": int(np.clip(rng.lognormal(12.3 if not malicious else 12.7, .9), 1024, 25_000_000)),
        "size_of_initialized_data": int(np.clip(rng.lognormal(12, 1.0), 0, 40_000_000)),
        "size_of_uninitialized_data": int(np.clip(rng.lognormal(9, 1.2), 0, 8_000_000)),
        "address_of_entry_point": int(rng.integers(256, 80_000)),
        "image_base": 4194304,
        "section_alignment": 4096,
        "file_alignment": 512,
        "major_os_version": 6,
        "major_subsystem_version": 6,
        "size_of_image": int(rng.lognormal(16.1 if not malicious else 16.5, .8)),
        "size_of_headers": 1024,
        "subsystem": 2,
        "dll_characteristics": 320,
        "size_of_stack_reserve": 1048576,
        "size_of_heap_reserve": 1048576,
        "number_of_rva_and_sizes": 16,
        "section_entropy_mean": float(np.clip(rng.normal(5.0 if not malicious else 6.1, .7), 0, 8)),
        "section_entropy_max": float(np.clip(rng.normal(6.2 if not malicious else 7.1, .45), 0, 8)),
        "section_entropy_min": float(np.clip(rng.normal(3.5, .8), 0, 8)),
        "section_entropy_std": float(np.clip(rng.normal(.8, .35), 0, 4)),
        "section_size_mean": float(rng.lognormal(12, .8)),
        "section_size_max": float(rng.lognormal(14, .8)),
        "section_virtual_ratio_mean": float(np.clip(rng.lognormal(0, .7), 0, 10)),
        "section_raw_ratio_mean": float(np.clip(rng.lognormal(0, .7), 0, 10)),
        "num_executable_sections": int(rng.integers(1, 3)),
        "num_writable_sections": int(rng.integers(0, 3)),
        "import_dll_count": int(np.clip(rng.normal(30 if not malicious else 22, 10), 0, 200)),
        "import_func_count": int(np.clip(rng.normal(450 if not malicious else 250, 120), 0, 3000)),
        "suspicious_import_count": int(np.clip(rng.poisson(.4 if not malicious else 2.8), 0, 20)),
        "has_import_table": 1,
        "string_count": int(np.clip(rng.normal(750 if not malicious else 520, 200), 0, 8000)),
        "string_mean_length": float(np.clip(rng.normal(15, 4), 1, 100)),
        "string_max_length": int(np.clip(rng.normal(140, 50), 0, 1000)),
        "printable_ratio": float(np.clip(rng.normal(.28, .09), 0, 1)),
        "url_count": int(rng.poisson(.3 if not malicious else 1.2)),
        "ip_count": int(rng.poisson(.2 if not malicious else .7)),
        "registry_count": int(rng.poisson(.2 if not malicious else 1.1)),
        "file_entropy": float(np.clip(rng.normal(5.1 if not malicious else 6.3, .65), 0, 8)),
        "byte_mean": float(np.clip(rng.normal(115, 15), 0, 255)),
        "byte_std": float(np.clip(rng.normal(75, 15), 0, 128)),
        "byte_zero_ratio": float(np.clip(rng.normal(.16, .07), 0, 1)),
        "byte_ff_ratio": float(np.clip(rng.normal(.02, .015), 0, 1)),
        "byte_printable_ratio": float(np.clip(rng.normal(.32, .1), 0, 1)),
        "has_rich_header": int(rng.random() < .75),
        "rich_header_entries": int(rng.integers(0, 30)),
        "rich_header_xor_key": int(rng.integers(0, 2**32)),
        "has_resource_dir": 1,
        "has_import_dir": 1,
        "has_export_dir": int(rng.random() < .3),
        "has_reloc_dir": int(rng.random() < .8),
        "has_debug_dir": int(rng.random() < .4),
        "has_tls_dir": int(rng.random() < .1),
        "has_security_dir": int(rng.random() < .2),
    })
    if family == "Ransomware":
        row["file_entropy"] += .8
        row["section_entropy_max"] = min(row["section_entropy_max"] + .5, 8)
        row["registry_count"] += 2
    elif family == "Trojan":
        row["suspicious_import_count"] += 3
        row["import_func_count"] += 80
    elif family == "Spyware":
        row["url_count"] += 3
        row["ip_count"] += 2
        row["suspicious_import_count"] += 2
    elif family == "Worm":
        row["import_dll_count"] += 8
        row["url_count"] += 2
    elif family == "Adware":
        row["url_count"] += 5
        row["string_count"] += 120
    size = max(row["size_of_image"], 1)
    row["size_of_code_ratio"] = row["size_of_code"] / size
    row["size_of_headers_ratio"] = row["size_of_headers"] / size
    row["entry_point_section_ratio"] = row["address_of_entry_point"] / size
    row["import_dll_mean"] = row["import_func_count"] / max(row["import_dll_count"], 1)
    row["import_func_mean"] = row["import_func_count"] / max(row["import_dll_count"], 1)
    row["num_suspicious_section_names"] = float(rng.random() < (.03 if not malicious else .12))
    return row


def main() -> None:
    rng = np.random.default_rng(SEED)
    records = []
    for family, count in COUNTS.items():
        for _ in range(count):
            record = generate_row(rng, family)
            record["family_label"] = FAMILIES.index(family)
            record["binary_label"] = int(family != "Benign")
            records.append(record)
    dataset = pd.DataFrame(records)
    dataset = dataset.sample(frac=1, random_state=SEED).reset_index(drop=True)
    out = ROOT / "ml_training" / "data" / "synthetic_dataset.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(out, index=False)
    (out.parent / "dataset_manifest.json").write_text(json.dumps({
        "source": "synthetic demonstration data generated by generate_synthetic_data.py",
        "seed": SEED,
        "rows": len(dataset),
        "feature_count": len(FeatureExtractor.get_feature_names()),
    }, indent=2), encoding="utf-8")
    print(f"Wrote {len(dataset)} synthetic rows with {len(FeatureExtractor.get_feature_names())} static features: {out}")


if __name__ == "__main__":
    main()
