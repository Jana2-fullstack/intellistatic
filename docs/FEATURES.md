# Static feature reference

This file documents the canonical extraction order emitted by `FeatureExtractor.get_feature_names()`. The project brief says 75 features but its enumerated groups add up to **77** (34 + 11 + 6 + 7 + 6 + 3 + 7 + 3). The analyzer preserves every explicitly listed feature. The application baseline uses a seven-field subset listed in `ml_training/train_pe_baseline.py`; retrain it if those fields or their order change.

## Header (34)

| Name | Description | Group |
|---|---|---|
| machine | COFF target architecture identifier. | Header |
| number_of_sections | Declared PE section count. | Header |
| time_date_stamp | COFF linker timestamp value. | Header |
| pointer_to_symbol_table | COFF symbol-table file offset. | Header |
| number_of_symbols | COFF symbol-table entry count. | Header |
| size_of_optional_header | Optional-header byte length. | Header |
| characteristics | COFF file characteristic flags. | Header |
| major_linker_version | Major linker version. | Header |
| minor_linker_version | Minor linker version. | Header |
| size_of_code | Declared code section bytes. | Header |
| size_of_initialized_data | Declared initialized-data bytes. | Header |
| size_of_uninitialized_data | Declared uninitialized-data bytes. | Header |
| address_of_entry_point | Relative virtual address of the entry point. | Header |
| base_of_code | RVA of the code section base. | Header |
| image_base | Preferred image load address. | Header |
| section_alignment | In-memory section alignment. | Header |
| file_alignment | On-disk section alignment. | Header |
| major_os_version | Minimum major operating-system version. | Header |
| minor_os_version | Minimum minor operating-system version. | Header |
| major_image_version | Major image version. | Header |
| minor_image_version | Minor image version. | Header |
| major_subsystem_version | Major subsystem version. | Header |
| minor_subsystem_version | Minor subsystem version. | Header |
| size_of_image | Declared image size after loading. | Header |
| size_of_headers | Combined PE header size. | Header |
| checksum | Optional-header checksum. | Header |
| subsystem | Target subsystem identifier. | Header |
| dll_characteristics | Optional-header DLL security flags. | Header |
| size_of_stack_reserve | Reserved stack size. | Header |
| size_of_stack_commit | Initially committed stack size. | Header |
| size_of_heap_reserve | Reserved heap size. | Header |
| size_of_heap_commit | Initially committed heap size. | Header |
| loader_flags | Legacy loader flags. | Header |
| number_of_rva_and_sizes | Declared data-directory count. | Header |

## Sections (11)

| Name | Description | Group |
|---|---|---|
| section_entropy_mean | Mean Shannon entropy across sections. | Sections |
| section_entropy_max | Highest section entropy. | Sections |
| section_entropy_min | Lowest section entropy. | Sections |
| section_entropy_std | Standard deviation of section entropy. | Sections |
| section_size_mean | Mean raw section size. | Sections |
| section_size_max | Largest raw section size. | Sections |
| section_virtual_ratio_mean | Mean virtual-size to raw-size ratio. | Sections |
| section_raw_ratio_mean | Mean raw-size to virtual-size ratio. | Sections |
| num_executable_sections | Count of sections marked executable. | Sections |
| num_writable_sections | Count of sections marked writable. | Sections |
| num_suspicious_section_names | Count matching the configured packer-name list. | Sections |

## Imports (6)

| Name | Description | Group |
|---|---|---|
| import_dll_count | Number of imported libraries. | Imports |
| import_func_count | Number of imported functions. | Imports |
| suspicious_import_count | Imports matching the configured suspicious API list. | Imports |
| import_dll_mean | Mean imported-function count per DLL. | Imports |
| import_func_mean | Mean imported-function count per DLL. | Imports |
| has_import_table | Whether an import table was parsed. | Imports |

## Strings (7)

| Name | Description | Group |
|---|---|---|
| string_count | Count of printable ASCII runs of at least four bytes. | Strings |
| string_mean_length | Mean length of extracted printable runs. | Strings |
| string_max_length | Longest extracted printable run. | Strings |
| printable_ratio | Fraction of bytes in the printable ASCII range. | Strings |
| url_count | Count of HTTP or HTTPS URL prefixes in extracted strings. | Strings |
| ip_count | Count of IPv4-shaped strings. | Strings |
| registry_count | Count of Windows registry path markers. | Strings |

## Byte level (6)

| Name | Description | Group |
|---|---|---|
| file_entropy | Shannon entropy of all file bytes. | Byte-level |
| byte_mean | Mean byte value. | Byte-level |
| byte_std | Standard deviation of byte values. | Byte-level |
| byte_zero_ratio | Fraction of zero bytes. | Byte-level |
| byte_ff_ratio | Fraction of 0xFF bytes. | Byte-level |
| byte_printable_ratio | Fraction of printable ASCII bytes. | Byte-level |

## Rich header (3)

| Name | Description | Group |
|---|---|---|
| has_rich_header | Whether a Rich header was parsed. | Rich Header |
| rich_header_entries | Number of parsed Rich-header values. | Rich Header |
| rich_header_xor_key | Parsed Rich-header XOR key. | Rich Header |

## Data directories (7)

| Name | Description | Group |
|---|---|---|
| has_resource_dir | Resource directory is present. | Data Directories |
| has_debug_dir | Debug directory is present. | Data Directories |
| has_tls_dir | TLS directory is present. | Data Directories |
| has_reloc_dir | Base-relocation directory is present. | Data Directories |
| has_import_dir | Import directory is present. | Data Directories |
| has_export_dir | Export directory is present. | Data Directories |
| has_security_dir | Certificate/security directory is present. | Data Directories |

## Composite ratios (3)

| Name | Description | Group |
|---|---|---|
| size_of_code_ratio | Code size divided by image size. | Composite |
| size_of_headers_ratio | Header size divided by image size. | Composite |
| entry_point_section_ratio | Entry-point RVA divided by image size. | Composite |
