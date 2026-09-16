#!/usr/bin/env python3
"""Generate the application icon set.

The icon is built here rather than committed as an opaque binary so that it can
be reviewed, reproduced, and regenerated at any size without an image library:
Tauri embeds the icon into the executable, and a binary nobody can inspect is a
poor thing to put in a security-sensitive build.

Usage:  python3 desktop/scripts/make-icon.py

Writes desktop/src-tauri/icons/icon.ico (the only icon tauri.conf.json
references) plus 32x32.png and 128x128.png for future use.

The ICO is written as an uncompressed 32-bit BGRA DIB rather than as a
PNG-compressed entry: both are valid in the format, but the DIB form is
universally understood by Windows, and a build that fails on an image-format
technicality is not worth the few hundred saved bytes.
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

ICON_DIR = Path(__file__).resolve().parent.parent / "src-tauri" / "icons"

# Dark theme to match the UI: a near-black disc with an accent ring, drawn in
# the same blue the dashboard uses for a healthy node.
BACKGROUND = (0x0F, 0x11, 0x15)
ACCENT = (0x4D, 0xA3, 0xFF)
INNER = (0x1B, 0x20, 0x2A)


def render(size: int) -> list[list[tuple[int, int, int, int]]]:
    """Render an RGBA square: a filled disc with an accent ring."""
    pixels: list[list[tuple[int, int, int, int]]] = []
    centre = (size - 1) / 2.0
    radius = size * 0.46
    ring_outer = size * 0.30
    ring_inner = size * 0.22

    for y in range(size):
        row: list[tuple[int, int, int, int]] = []
        for x in range(size):
            distance = math.hypot(x - centre, y - centre)
            if distance > radius:
                row.append((0, 0, 0, 0))
                continue

            # Supersample the edge only, which is where aliasing is visible.
            alpha = 255
            if distance > radius - 1:
                coverage = max(0.0, radius - distance)
                alpha = int(round(255 * min(1.0, coverage)))
                if alpha == 0:
                    row.append((0, 0, 0, 0))
                    continue

            if ring_inner <= distance <= ring_outer:
                red, green, blue = ACCENT
            elif distance < ring_inner:
                red, green, blue = INNER
            else:
                red, green, blue = BACKGROUND
            row.append((red, green, blue, alpha))
        pixels.append(row)
    return pixels


def ico_bytes(pixels: list[list[tuple[int, int, int, int]]]) -> bytes:
    size = len(pixels)

    # DIB pixel data is stored bottom-up and in BGRA order.
    body = bytearray()
    for y in range(size - 1, -1, -1):
        for (red, green, blue, alpha) in pixels[y]:
            body += bytes((blue, green, red, alpha))
    # The AND mask must be present even when every pixel has an alpha channel.
    mask_stride = ((size + 31) // 32) * 4
    body += bytes(mask_stride * size)

    header = struct.pack(
        "<IiiHHIIiiII",
        40,           # BITMAPINFOHEADER size
        size,         # width
        size * 2,     # height: colour data plus AND mask
        1,            # planes
        32,           # bits per pixel
        0,            # BI_RGB
        len(body),    # image size
        0, 0,         # pixels per metre
        0, 0,         # palette entries
    )

    image = header + bytes(body)
    directory = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(image), 22)
    return directory + entry + image


def zlib_stored(data: bytes) -> bytes:
    """Wrap `data` in a zlib stream built from stored (uncompressed) blocks.

    Compressed output is not byte-identical across builds of zlib itself, so a
    reproducibility check that hashes a compressed PNG fails on another machine
    for a reason that has nothing to do with the icon -- which is exactly what
    happened the first time this ran in CI. Stored blocks are trivially
    deterministic, and these files are a few kilobytes either way.
    """
    out = bytearray(b"\x78\x01")  # CMF/FLG: deflate, 32 KiB window, no preset dict
    remaining = data
    while True:
        block = remaining[:65535]
        remaining = remaining[65535:]
        out.append(1 if not remaining else 0)  # BFINAL on the final block only
        out += struct.pack("<HH", len(block), 0xFFFF ^ len(block))
        out += block
        if not remaining:
            break
    out += struct.pack(">I", zlib.adler32(data) & 0xFFFFFFFF)
    return bytes(out)


def png_bytes(pixels: list[list[tuple[int, int, int, int]]]) -> bytes:
    size = len(pixels)

    raw = bytearray()
    for row in pixels:
        raw.append(0)  # filter type 0 (None)
        for (red, green, blue, alpha) in row:
            raw += bytes((red, green, blue, alpha))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib_stored(bytes(raw)))
        + chunk(b"IEND", b"")
    )


def main() -> None:
    ICON_DIR.mkdir(parents=True, exist_ok=True)

    icon = render(32)
    (ICON_DIR / "icon.ico").write_bytes(ico_bytes(icon))
    print(f"wrote {ICON_DIR / 'icon.ico'}")

    for size in (32, 128):
        path = ICON_DIR / f"{size}x{size}.png"
        path.write_bytes(png_bytes(render(size)))
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
