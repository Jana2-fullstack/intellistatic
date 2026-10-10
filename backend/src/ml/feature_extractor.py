import logging
import math
import re
import numpy as np

logger = logging.getLogger(__name__)

HEADER_FEATURES = [
    "machine", "number_of_sections", "time_date_stamp", "pointer_to_symbol_table",
    "number_of_symbols", "size_of_optional_header", "characteristics",
    "major_linker_version", "minor_linker_version", "size_of_code",
    "size_of_initialized_data", "size_of_uninitialized_data", "address_of_entry_point",
    "base_of_code", "image_base", "section_alignment", "file_alignment", "major_os_version",
    "minor_os_version", "major_image_version", "minor_image_version", "major_subsystem_version",
    "minor_subsystem_version", "size_of_image", "size_of_headers", "checksum", "subsystem",
    "dll_characteristics", "size_of_stack_reserve", "size_of_stack_commit",
    "size_of_heap_reserve", "size_of_heap_commit", "loader_flags", "number_of_rva_and_sizes",
]
SECTION_FEATURES = [
    "section_entropy_mean", "section_entropy_max", "section_entropy_min", "section_entropy_std",
    "section_size_mean", "section_size_max", "section_virtual_ratio_mean", "section_raw_ratio_mean",
    "num_executable_sections", "num_writable_sections", "num_suspicious_section_names",
]
IMPORT_FEATURES = [
    "import_dll_count", "import_func_count", "suspicious_import_count", "import_dll_mean",
    "import_func_mean", "has_import_table",
]
STRING_FEATURES = [
    "string_count", "string_mean_length", "string_max_length", "printable_ratio",
    "url_count", "ip_count", "registry_count",
]
BYTE_FEATURES = [
    "file_entropy", "byte_mean", "byte_std", "byte_zero_ratio", "byte_ff_ratio", "byte_printable_ratio",
]
RICH_FEATURES = ["has_rich_header", "rich_header_entries", "rich_header_xor_key"]
DIRECTORY_FEATURES = [
    "has_resource_dir", "has_debug_dir", "has_tls_dir", "has_reloc_dir", "has_import_dir",
    "has_export_dir", "has_security_dir",
]
COMPOSITE_FEATURES = ["size_of_code_ratio", "size_of_headers_ratio", "entry_point_section_ratio"]
FEATURE_NAMES = (
    HEADER_FEATURES + SECTION_FEATURES + IMPORT_FEATURES + STRING_FEATURES + BYTE_FEATURES
    + RICH_FEATURES + DIRECTORY_FEATURES + COMPOSITE_FEATURES
)

SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread",
    "setwindowshookex", "getasynckeystate", "regsetvalueex", "createservice",
    "urldownloadtofile", "winexec", "shellexecute", "cryptencrypt", "cryptdecrypt",
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "loadlibrary", "getprocaddress", "adjusttokenprivileges", "openprocesstoken",
}
SUSPICIOUS_SECTIONS = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".mpress", ".themida", ".vmp0",
    ".vmp1", ".enigma", ".packed", ".petite",
}
HEADER_MAP = {
    "machine": "Machine", "number_of_sections": "NumberOfSections", "time_date_stamp": "TimeDateStamp",
    "pointer_to_symbol_table": "PointerToSymbolTable", "number_of_symbols": "NumberOfSymbols",
    "size_of_optional_header": "SizeOfOptionalHeader", "characteristics": "Characteristics",
}
OPTIONAL_MAP = {
    "major_linker_version": "MajorLinkerVersion", "minor_linker_version": "MinorLinkerVersion",
    "size_of_code": "SizeOfCode", "size_of_initialized_data": "SizeOfInitializedData",
    "size_of_uninitialized_data": "SizeOfUninitializedData", "address_of_entry_point": "AddressOfEntryPoint",
    "base_of_code": "BaseOfCode", "image_base": "ImageBase", "section_alignment": "SectionAlignment",
    "file_alignment": "FileAlignment", "major_os_version": "MajorOperatingSystemVersion",
    "minor_os_version": "MinorOperatingSystemVersion", "major_image_version": "MajorImageVersion",
    "minor_image_version": "MinorImageVersion", "major_subsystem_version": "MajorSubsystemVersion",
    "minor_subsystem_version": "MinorSubsystemVersion", "size_of_image": "SizeOfImage",
    "size_of_headers": "SizeOfHeaders", "checksum": "CheckSum", "subsystem": "Subsystem",
    "dll_characteristics": "DllCharacteristics", "size_of_stack_reserve": "SizeOfStackReserve",
    "size_of_stack_commit": "SizeOfStackCommit", "size_of_heap_reserve": "SizeOfHeapReserve",
    "size_of_heap_commit": "SizeOfHeapCommit", "loader_flags": "LoaderFlags",
    "number_of_rva_and_sizes": "NumberOfRvaAndSizes",
}
DIRECTORY_INDEXES = {
    "has_resource_dir": 2, "has_debug_dir": 6, "has_tls_dir": 9, "has_reloc_dir": 5,
    "has_import_dir": 1, "has_export_dir": 0, "has_security_dir": 4,
}


def _number(value: object) -> float:
    try:
        if hasattr(value, "value"):
            value = value.value
        result = float(value)  # type: ignore[arg-type]
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


class FeatureExtractor:
    @staticmethod
    def get_feature_names() -> list[str]:
        return FEATURE_NAMES.copy()

    @staticmethod
    def is_valid_pe(data: bytes) -> bool:
        """Validate DOS/NT and optional-header signatures without executing bytes."""
        if not isinstance(data, bytes) or len(data) < 0x40 or data[:2] != b"MZ":
            return False
        try:
            import pefile

            parsed = pefile.PE(data=data, fast_load=True)
            return (
                parsed.NT_HEADERS.Signature == 0x4550
                and parsed.OPTIONAL_HEADER.Magic in (0x10B, 0x20B)
            )
        except Exception:
            return False

    def extract(self, data: bytes) -> dict[str, float]:
        """Return the fixed-order 77-feature vector; parser errors degrade to zeros."""
        features = {name: 0.0 for name in FEATURE_NAMES}
        if not isinstance(data, bytes) or not data:
            return features

        self._extract_byte_features(data, features)
        self._extract_string_features(data, features)
        self._extract_with_pefile(data, features)
        self._extract_with_lief(data, features)
        self._extract_ratios(features)
        return {name: _number(features.get(name, 0.0)) for name in FEATURE_NAMES}

    @staticmethod
    def _extract_byte_features(data: bytes, output: dict[str, float]) -> None:
        try:
            values = np.frombuffer(data, dtype=np.uint8)
            counts = np.bincount(values, minlength=256)
            size = len(data)
            output["file_entropy"] = -sum(
                (count / size) * math.log2(count / size) for count in counts if count
            )
            output["byte_mean"] = float(values.mean())
            output["byte_std"] = float(values.std())
            output["byte_zero_ratio"] = float(counts[0] / size)
            output["byte_ff_ratio"] = float(counts[255] / size)
            output["byte_printable_ratio"] = float(counts[32:127].sum() / size)
        except Exception:
            logger.debug("Byte feature extraction failed", exc_info=True)

    @staticmethod
    def _extract_string_features(data: bytes, output: dict[str, float]) -> None:
        try:
            count = 0
            total_length = 0
            maximum_length = 0
            for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
                length = match.end() - match.start()
                count += 1
                total_length += length
                maximum_length = max(maximum_length, length)
            output["string_count"] = count
            output["string_mean_length"] = total_length / count if count else 0.0
            output["string_max_length"] = maximum_length
            output["printable_ratio"] = output["byte_printable_ratio"]
            output["url_count"] = sum(1 for _ in re.finditer(rb"https?://", data, flags=re.IGNORECASE))
            output["ip_count"] = sum(1 for _ in re.finditer(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", data))
            output["registry_count"] = sum(1 for _ in re.finditer(rb"(?:hkey_|\\registry\\)", data, flags=re.IGNORECASE))
        except Exception:
            logger.debug("String feature extraction failed", exc_info=True)

    def _extract_with_pefile(self, data: bytes, output: dict[str, float]) -> None:
        try:
            import pefile

            pe = pefile.PE(data=data, fast_load=False)
        except Exception:
            logger.debug("pefile could not parse payload", exc_info=True)
            return
        try:
            file_header = pe.FILE_HEADER
            optional = pe.OPTIONAL_HEADER
            for feature, attribute in HEADER_MAP.items():
                output[feature] = _number(getattr(file_header, attribute, 0))
            for feature, attribute in OPTIONAL_MAP.items():
                output[feature] = _number(getattr(optional, attribute, 0))

            sections = list(pe.sections)
            entropies = [_number(section.get_entropy()) for section in sections]
            raw_sizes = [_number(section.SizeOfRawData) for section in sections]
            virtual_ratios = [
                _number(section.Misc_VirtualSize) / max(_number(section.SizeOfRawData), 1.0)
                for section in sections
            ]
            raw_ratios = [
                _number(section.SizeOfRawData) / max(_number(section.Misc_VirtualSize), 1.0)
                for section in sections
            ]
            output["section_entropy_mean"] = _mean(entropies)
            output["section_entropy_max"] = max(entropies, default=0.0)
            output["section_entropy_min"] = min(entropies, default=0.0)
            output["section_entropy_std"] = math.sqrt(_mean([(x - _mean(entropies)) ** 2 for x in entropies])) if entropies else 0.0
            output["section_size_mean"] = _mean(raw_sizes)
            output["section_size_max"] = max(raw_sizes, default=0.0)
            output["section_virtual_ratio_mean"] = _mean(virtual_ratios)
            output["section_raw_ratio_mean"] = _mean(raw_ratios)
            output["num_executable_sections"] = sum(bool(_number(s.Characteristics) & 0x20000000) for s in sections)
            output["num_writable_sections"] = sum(bool(_number(s.Characteristics) & 0x80000000) for s in sections)
            output["num_suspicious_section_names"] = sum(
                s.Name.rstrip(b"\0").decode("ascii", "ignore").lower() in SUSPICIOUS_SECTIONS for s in sections
            )

            imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
            dll_function_counts: list[float] = []
            suspicious = 0
            for imported_dll in imports:
                functions = getattr(imported_dll, "imports", []) or []
                dll_function_counts.append(float(len(functions)))
                for function in functions:
                    name = getattr(function, "name", None)
                    if name and name.decode("ascii", "ignore").lower() in SUSPICIOUS_IMPORTS:
                        suspicious += 1
            output["import_dll_count"] = len(imports)
            output["import_func_count"] = sum(dll_function_counts)
            output["suspicious_import_count"] = suspicious
            output["import_dll_mean"] = _mean(dll_function_counts)
            output["import_func_mean"] = _mean(dll_function_counts)
            output["has_import_table"] = float(bool(imports))

            try:
                rich = pe.parse_rich_header()
                entries = rich.get("values", []) if rich else []
                output["has_rich_header"] = float(bool(rich))
                output["rich_header_entries"] = len(entries)
                output["rich_header_xor_key"] = _number(rich.get("key", 0)) if rich else 0.0
            except Exception:
                pass

            directories = getattr(optional, "DATA_DIRECTORY", [])
            for feature, index in DIRECTORY_INDEXES.items():
                if index < len(directories):
                    directory = directories[index]
                    output[feature] = float(bool(_number(directory.VirtualAddress) or _number(directory.Size)))
        except Exception:
            logger.debug("pefile feature group extraction failed", exc_info=True)
        finally:
            try:
                pe.close()
            except Exception:
                pass

    def _extract_with_lief(self, data: bytes, output: dict[str, float]) -> None:
        try:
            import lief

            binary = lief.PE.parse(data)
            if binary is None:
                return
        except Exception:
            logger.debug("LIEF could not parse payload", exc_info=True)
            return
        try:
            header = binary.header
            for feature, attribute in {
                "machine": "machine", "number_of_sections": "numberof_sections",
                "time_date_stamp": "time_date_stamps", "pointer_to_symbol_table": "pointerto_symbol_table",
                "number_of_symbols": "numberof_symbols", "size_of_optional_header": "sizeof_optional_header",
                "characteristics": "characteristics",
            }.items():
                value = getattr(header, attribute, None)
                if value is not None:
                    output[feature] = _number(value)
            optional = binary.optional_header
            for feature, attribute in {
                "major_linker_version": "major_linker_version", "minor_linker_version": "minor_linker_version",
                "size_of_code": "sizeof_code", "size_of_initialized_data": "sizeof_initialized_data",
                "size_of_uninitialized_data": "sizeof_uninitialized_data", "address_of_entry_point": "addressof_entrypoint",
                "base_of_code": "baseof_code", "image_base": "imagebase", "section_alignment": "section_alignment",
                "file_alignment": "file_alignment", "major_os_version": "major_operating_system_version",
                "minor_os_version": "minor_operating_system_version", "major_image_version": "major_image_version",
                "minor_image_version": "minor_image_version", "major_subsystem_version": "major_subsystem_version",
                "minor_subsystem_version": "minor_subsystem_version", "size_of_image": "sizeof_image",
                "size_of_headers": "sizeof_headers", "checksum": "checksum", "subsystem": "subsystem",
                "dll_characteristics": "dll_characteristics", "size_of_stack_reserve": "sizeof_stack_reserve",
                "size_of_stack_commit": "sizeof_stack_commit", "size_of_heap_reserve": "sizeof_heap_reserve",
                "size_of_heap_commit": "sizeof_heap_commit", "loader_flags": "loader_flags",
                "number_of_rva_and_sizes": "numberof_rva_and_size",
            }.items():
                value = getattr(optional, attribute, None)
                if value is not None:
                    output[feature] = _number(value)
            sections = list(binary.sections)
            if sections:
                entropy = [_number(section.entropy) for section in sections]
                sizes = [_number(section.size) for section in sections]
                output["section_entropy_mean"] = _mean(entropy)
                output["section_entropy_max"] = max(entropy, default=0.0)
                output["section_entropy_min"] = min(entropy, default=0.0)
                output["section_entropy_std"] = math.sqrt(_mean([(x - _mean(entropy)) ** 2 for x in entropy]))
                output["section_size_mean"] = _mean(sizes)
                output["section_size_max"] = max(sizes, default=0.0)
                output["num_executable_sections"] = sum("MEM_EXECUTE" in str(s.characteristics_lists) for s in sections)
                output["num_writable_sections"] = sum("MEM_WRITE" in str(s.characteristics_lists) for s in sections)
                output["num_suspicious_section_names"] = sum(str(s.name).rstrip("\0").lower() in SUSPICIOUS_SECTIONS for s in sections)
        except Exception:
            logger.debug("LIEF enrichment failed", exc_info=True)

    @staticmethod
    def _extract_ratios(features: dict[str, float]) -> None:
        size = max(features.get("size_of_image", 0.0), 1.0)
        features["size_of_code_ratio"] = features.get("size_of_code", 0.0) / size
        features["size_of_headers_ratio"] = features.get("size_of_headers", 0.0) / size
        features["entry_point_section_ratio"] = features.get("address_of_entry_point", 0.0) / size
