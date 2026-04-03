"""Markdown chunking — split documents by H2 headers for semantic indexing."""

import re
from pathlib import Path

from .models import Chunk
from .parser import parse_metadata

# Split on H2 headers (## )
_H2_SPLIT_RE = re.compile(r"(?=^## )", re.MULTILINE)

# Extract H2 header text
_H2_TEXT_RE = re.compile(r"^## +(.+)", re.MULTILINE)


def chunk_document(vault_root: Path, rel_path: str) -> list[Chunk]:
    """Split a markdown file into chunks by H2 headers.

    Returns one chunk per H2 section, plus a preamble chunk for content
    before the first H2. Files without H2 headers produce a single chunk.
    """
    full_path = vault_root / rel_path
    content = full_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # Get title from metadata
    meta = parse_metadata(lines)
    doc_title = meta.title or Path(rel_path).stem

    # Split on H2 boundaries
    sections = _H2_SPLIT_RE.split(content)

    if len(sections) <= 1:
        # No H2 headers — single chunk for entire file
        text = content.strip()
        if len(text) < 20:
            return []
        return [
            Chunk(
                doc_path=rel_path,
                doc_title=doc_title,
                section_header="",
                content=text,
                embedding_text=f"{doc_title} ({rel_path})\n\n{text}",
                start_line=1,
            )
        ]

    chunks: list[Chunk] = []
    current_line = 1

    for i, section_text in enumerate(sections):
        text = section_text.strip()
        if len(text) < 20:
            current_line += section_text.count("\n") + 1
            continue

        if i == 0:
            # Preamble — content before first H2
            header = ""
        else:
            # Extract H2 header text
            m = _H2_TEXT_RE.match(section_text)
            header = m.group(1).strip() if m else ""

        # Build contextualized text for embedding
        if header:
            embedding_text = f"{doc_title} ({rel_path}) > {header}\n\n{text}"
        else:
            embedding_text = f"{doc_title} ({rel_path})\n\n{text}"

        chunks.append(
            Chunk(
                doc_path=rel_path,
                doc_title=doc_title,
                section_header=header or "preamble",
                content=text,
                embedding_text=embedding_text,
                start_line=current_line,
            )
        )

        current_line += section_text.count("\n") + 1

    return chunks
