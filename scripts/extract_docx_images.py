#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path
from zipfile import ZipFile


def extract_images_from_docx(docx_path: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    with ZipFile(docx_path) as z:
        # Collect media files inside word/media/
        media_files = [
            i for i in z.infolist() if i.filename.startswith("word/media/")
        ]
        if not media_files:
            return []

        # Sort by numeric index if present (image1.png, image2.jpeg, ...), fallback to name
        def sort_key(info):
            name = Path(info.filename).name  # imageN.ext
            m = re.match(r"image(\d+)\.[^.]+$", name, re.IGNORECASE)
            return (int(m.group(1)) if m else 10**9, name)

        media_files.sort(key=sort_key)

        mapping = []  # list of (src_zip_name, out_filename)
        for idx, info in enumerate(media_files, start=1):
            name = Path(info.filename).name
            ext = Path(name).suffix.lower()  # .png/.jpeg/.jpg/.gif/...
            out_name = f"img{idx:02d}{ext}"
            data = z.read(info)
            (out_dir / out_name).write_bytes(data)
            mapping.append((info.filename, out_name))
        return mapping


def replace_md_images(md_path: Path, out_web_dir: str, count: int):
    # out_web_dir is like '/images/SUCTF2025'
    text = md_path.read_text(encoding="utf-8")

    # Pattern for markdown images: ![alt](url)
    img_pat = re.compile(r"!\[([^\]]*)\]\(([^\)]+)\)")

    # Find all images
    matches = list(img_pat.finditer(text))
    if not matches:
        return 0, 0, text

    # Replace sequentially up to 'count'
    new_text_parts = []
    last_index = 0
    replaced = 0
    for i, m in enumerate(matches):
        new_text_parts.append(text[last_index:m.start()])
        alt = m.group(1)
        url = m.group(2)

        if replaced < count:
            # Use extension by sequence; assume png by default; try to infer from existing URL
            # Better: pick ext by replaced index aligned with extracted files
            # We will set ext placeholder, actual ext resolved by file existence below
            ext = None
            # Try to detect ext from original url
            m_ext = re.search(r"\.(png|jpe?g|gif|webp|bmp|tiff)(?:\?|#|$)", url, re.IGNORECASE)
            if m_ext:
                ext = "." + m_ext.group(1).lower().replace("jpg", "jpeg")
            # If not found, rely on common set by probing
            if not ext:
                # We'll probe several possible extensions
                candidates = [".png", ".jpeg", ".jpg", ".gif", ".webp"]
                # We don't have filesystem context here; ext will be decided later by checking files
                # For now keep ext None; we'll try .png as default
                ext = ".png"

            # However, to accurately match extensions created during extraction,
            # we attempt to read from the filesystem using the numbered file.
            num = replaced + 1
            possible_exts = [".png", ".jpeg", ".jpg", ".gif", ".webp", ".bmp", ".tiff"]
            found_ext = None
            for e in possible_exts:
                p = Path("public") / out_web_dir.strip("/") / f"img{num:02d}{e}"
                if p.exists():
                    found_ext = e
                    break
            if found_ext:
                ext = found_ext

            new_url = f"{out_web_dir}/img{num:02d}{ext}"
            new_text_parts.append(f"![{alt}]({new_url})")
            replaced += 1
        else:
            # Keep as is if we have more images in MD than in DOCX
            new_text_parts.append(m.group(0))
        last_index = m.end()
    new_text_parts.append(text[last_index:])
    new_text = "".join(new_text_parts)
    return len(matches), replaced, new_text


def main():
    ap = argparse.ArgumentParser(description="Extract images from DOCX and rewrite MD image links.")
    ap.add_argument("--docx", required=True, help="Path to DOCX file")
    ap.add_argument("--md", required=True, help="Path to target Markdown file")
    ap.add_argument("--outdir", required=False, help="Output dir under public/images, defaults from MD name")
    args = ap.parse_args()

    docx_path = Path(args.docx)
    md_path = Path(args.md)
    if not docx_path.exists():
        print(f"[error] DOCX not found: {docx_path}", file=sys.stderr)
        sys.exit(1)
    if not md_path.exists():
        print(f"[error] MD not found: {md_path}", file=sys.stderr)
        sys.exit(1)

    # Derive out web dir: /images/<slug>
    if args.outdir:
        slug = Path(args.outdir).name
    else:
        slug = md_path.stem
    out_dir_fs = Path("public/images") / slug
    out_web_dir = f"/images/{slug}"

    print(f"[info] Extracting images from {docx_path} -> {out_dir_fs}")
    mapping = extract_images_from_docx(docx_path, out_dir_fs)
    print(f"[info] Extracted {len(mapping)} image(s)")

    # No backup by default per user request. If needed later, can re-enable.

    total, replaced, new_text = replace_md_images(md_path, out_web_dir, len(mapping))
    md_path.write_text(new_text, encoding="utf-8")
    print(f"[info] MD images found: {total}; replaced: {replaced}")
    if replaced < total:
        print("[warn] Fewer images in DOCX than in MD; remaining links kept.")
    if replaced < len(mapping):
        print("[warn] More images in DOCX than in MD; extra images saved but unused.")


if __name__ == "__main__":
    main()
