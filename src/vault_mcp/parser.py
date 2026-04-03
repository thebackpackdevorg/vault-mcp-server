"""Markdown parsing — metadata extraction, sections, cross-references."""

import re
from pathlib import Path

from .models import Metadata, VaultDocument

# **Key:** Value pattern in first 15 lines
_META_RE = re.compile(r"\*\*(.+?):\*\*\s*(.+)")

# Markdown links to .md files
_LINK_RE = re.compile(r"\[.*?\]\(([^)]+\.md)\)")

# Header pattern
_HEADER_RE = re.compile(r"^(#{1,4})\s+(.+)", re.MULTILINE)

# Status normalization mapping
_STATUS_MAP: dict[str, str] = {
    "active": "Active",
    "activo": "Active",
    "en progreso": "Active",
    "draft": "Active",
    "🟡": "Active",
    "pending": "Pending",
    "pendiente": "Pending",
    "🔴": "Pending",
    "paused": "Paused",
    "pausado": "Paused",
    "⏸️": "Paused",
    "done": "Done",
    "completado": "Done",
    "completed": "Done",
    "🟢": "Done",
}

# Metadata key normalization
_KEY_MAP: dict[str, str] = {
    "creado": "created_date",
    "created": "created_date",
    "status": "status",
    "estado": "status",
    "última actualización": "updated_date",
    "ultima actualización": "updated_date",
    "last updated": "updated_date",
    "updated": "updated_date",
}


def normalize_status(raw: str) -> str:
    """Normalize status strings and emojis to standard vocabulary."""
    cleaned = raw.strip().lower()
    # Check emoji first (they may be prefix in table cells like "🔴 Pendiente")
    for token, normalized in _STATUS_MAP.items():
        if token in cleaned:
            return normalized
    return raw.strip()


def parse_metadata(lines: list[str]) -> Metadata:
    """Extract metadata from the first 15 lines of a markdown file."""
    meta = Metadata(raw={})
    scan_lines = lines[:15]

    for line in scan_lines:
        m = _META_RE.search(line)
        if m:
            key_raw = m.group(1).strip()
            value = m.group(2).strip()
            meta.raw[key_raw] = value

            key_norm = _KEY_MAP.get(key_raw.lower())
            if key_norm == "created_date":
                meta.created_date = value
            elif key_norm == "updated_date":
                meta.updated_date = value
            elif key_norm == "status":
                meta.status = normalize_status(value)

    # Title: first H1, or first non-empty line
    for line in lines[:5]:
        stripped = line.strip()
        if stripped.startswith("# "):
            meta.title = stripped[2:].strip()
            break
        elif stripped and not stripped.startswith("---") and meta.title is None:
            meta.title = stripped

    return meta


def extract_sections(content: str) -> list[str]:
    """Extract header names from markdown content."""
    return [m.group(2).strip() for m in _HEADER_RE.finditer(content)]


def extract_cross_references(content: str) -> list[str]:
    """Extract unique .md file references from markdown links."""
    refs = _LINK_RE.findall(content)
    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            unique.append(ref)
    return unique


def parse_document(vault_root: Path, rel_path: str) -> VaultDocument:
    """Parse a markdown file into a VaultDocument with metadata."""
    full_path = vault_root / rel_path
    content = full_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    metadata = parse_metadata(lines)
    sections = extract_sections(content)
    cross_refs = extract_cross_references(content)

    return VaultDocument(
        path=rel_path,
        content=content,
        metadata=metadata,
        sections=sections,
        cross_references=cross_refs,
    )


def infer_domain(rel_path: str) -> str:
    """Infer domain from the file's top-level directory."""
    parts = Path(rel_path).parts
    if len(parts) > 1:
        return parts[0]
    return "root"
