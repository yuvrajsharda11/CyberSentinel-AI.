"""
Static file security analysis. Never executes the uploaded file.

Upgrades over the original version:
  - Wider magic-byte signature table (archives, ELF, Mach-O, RTF/OLE, scripts).
  - Extension-vs-content mismatch ("masquerading") detection, e.g. a
    Windows PE executable renamed to look like a .pdf or .jpg.
  - Office macro detection: flags vbaProject.bin inside modern (ZIP-based)
    Office documents.
  - Lightweight, dependency-free PE header parsing: section count/names,
    compile timestamp, and known-suspicious section names (e.g. UPX packer
    markers) for Windows executables.
  - Expanded suspicious-string list (LOLBins, common script droppers).
"""
import hashlib
import io
import math
import struct
import zipfile

MAGIC = [
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP/Office archive"),
    (b"MZ", "Windows PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable (64-bit)"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable (32-bit)"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"{\\rtf", "RTF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Legacy OLE document (.doc/.xls/.ppt)"),
    (b"#!", "Script with shebang"),
]

# extension -> set of "detected type" labels considered a normal pairing
EXPECTED_TYPES_FOR_EXT = {
    ".pdf": {"PDF"},
    ".zip": {"ZIP/Office archive"},
    ".docx": {"ZIP/Office archive"}, ".xlsx": {"ZIP/Office archive"}, ".pptx": {"ZIP/Office archive"},
    ".doc": {"Legacy OLE document (.doc/.xls/.ppt)"},
    ".xls": {"Legacy OLE document (.doc/.xls/.ppt)"},
    ".ppt": {"Legacy OLE document (.doc/.xls/.ppt)"},
    ".png": {"PNG image"},
    ".jpg": {"JPEG image"}, ".jpeg": {"JPEG image"},
    ".gif": {"GIF image"},
    ".rar": {"RAR archive"},
    ".7z": {"7-Zip archive"},
    ".gz": {"GZIP archive"},
    ".rtf": {"RTF document"},
    ".exe": {"Windows PE executable"}, ".dll": {"Windows PE executable"},
    ".elf": {"ELF executable"},
    ".sh": {"Script with shebang", "Unknown"},
}

SUSPICIOUS_STRINGS = [
    b"powershell", b"cmd.exe", b"wscript", b"cscript", b"rundll32", b"regsvr32",
    b"mshta", b"certutil", b"bitsadmin", b"vbaProject", b"schtasks", b"reg add",
    b"invoke-expression", b"iex(", b"downloadstring", b"frombase64string",
    b"createobject(\"wscript.shell\")",
]


def entropy(data):
    if not data:
        return 0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _detect_type(data):
    for magic, label in MAGIC:
        if data.startswith(magic):
            return label
    return "Unknown"


def _check_masquerade(name, kind):
    ext = ""
    if "." in name:
        ext = "." + name.rsplit(".", 1)[-1].lower()
    expected = EXPECTED_TYPES_FOR_EXT.get(ext)
    if expected and kind != "Unknown" and kind not in expected:
        return f"File extension '{ext}' does not match detected content type '{kind}' (possible masquerading)"
    return None


def _check_office_macros(data):
    """Modern (ZIP-based) Office files store VBA macros in vbaProject.bin."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            if any("vbaProject.bin" in n for n in names):
                return True
    except Exception:
        pass
    return False


def _parse_pe_header(data):
    """Very small, dependency-free PE header reader. Returns a dict or None.
    Only reads header metadata — never loads/executes anything."""
    try:
        if not data.startswith(b"MZ") or len(data) < 0x40:
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            return None
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff_offset = e_lfanew + 4
        machine, num_sections, timestamp = struct.unpack_from("<HHI", data, coff_offset)
        opt_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
        section_table_offset = coff_offset + 20 + opt_header_size

        machine_map = {0x014c: "x86 (32-bit)", 0x8664: "x64", 0x01c0: "ARM", 0xaa64: "ARM64"}
        sections = []
        suspicious_sections = []
        known_suspicious = {"upx0", "upx1", "upx2", ".textbss", ".packed"}
        for i in range(min(num_sections, 96)):  # sanity cap
            off = section_table_offset + i * 40
            if off + 40 > len(data):
                break
            raw_name = data[off:off + 8].rstrip(b"\x00").decode(errors="ignore")
            sections.append(raw_name)
            if raw_name.lower() in known_suspicious:
                suspicious_sections.append(raw_name)

        return {
            "machine": machine_map.get(machine, hex(machine)),
            "num_sections": num_sections,
            "compile_timestamp_unix": timestamp,
            "section_names": sections,
            "suspicious_sections": suspicious_sections,
        }
    except Exception:
        return None


def analyze_file(name, data):
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    kind = _detect_type(data)

    indicators = []
    if kind in {"Windows PE executable", "ELF executable",
                "Mach-O executable (64-bit)", "Mach-O executable (32-bit)"}:
        indicators.append("Executable binary")

    masquerade = _check_masquerade(name, kind)
    if masquerade:
        indicators.append(masquerade)

    e = entropy(data[:2_000_000])
    if e > 7.2:
        indicators.append("High entropy; may indicate compression/encryption/packing")

    lower = data[:5_000_000].lower()
    found_strings = [s.decode(errors="ignore") for s in SUSPICIOUS_STRINGS if s in lower]
    for s in found_strings:
        indicators.append("Suspicious string: " + s)

    has_macros = False
    if kind == "ZIP/Office archive":
        has_macros = _check_office_macros(data)
        if has_macros:
            indicators.append("Contains embedded VBA macro (vbaProject.bin)")

    pe_info = None
    if kind == "Windows PE executable":
        pe_info = _parse_pe_header(data)
        if pe_info and pe_info["suspicious_sections"]:
            indicators.append("Packer-associated section name(s): " +
                               ", ".join(pe_info["suspicious_sections"]))

    score = min(100, len(indicators) * 18 + (10 if e > 7.2 else 0)
                + (15 if masquerade else 0) + (15 if has_macros else 0))

    return {
        "risk_score": score,
        "filename": name,
        "size_bytes": len(data),
        "sha256": sha256,
        "md5": md5,
        "detected_type": kind,
        "entropy": round(e, 3),
        "extension_mismatch": bool(masquerade),
        "contains_macros": has_macros,
        "pe_info": pe_info,
        "indicators": indicators,
    }
