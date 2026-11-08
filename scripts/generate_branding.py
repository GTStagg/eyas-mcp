"""Generate the eyas-mcp logo, mark and social preview.

eyas-mcp shares its look with Eyas, the console built on it. An eyas is a young
falcon in training. The mark is Eyas's Falcon-A: a capital "A" with a falcon's wings
spreading from the apex, in vendor red on true black. It is drawn to stay distinct
from CrowdStrike's own falcon logo.

The lettering matches Eyas: Inter Tight ExtraBold, tracked uppercase, with JetBrains
Mono for the tagline. Both fonts are under the SIL Open Font License, and the SVG
text is converted to outlines so it looks the same everywhere.

This script isn't part of the server and needs extra packages and fonts:

    python -m pip install fonttools pillow
    # Fonts: InterTight[wght].ttf and JetBrainsMono[wght].ttf from
    # https://github.com/google/fonts/tree/main/ofl
    python scripts/generate_branding.py --sans InterTight.ttf --mono JetBrainsMono.ttf

Outputs go to docs/assets/.
"""

import argparse
import math
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ASSETS = Path(__file__).resolve().parent.parent / "docs" / "assets"

# Eyas palette (the Eyas console's theme colours)
RED_900 = "#7f1d1d"
RED_700 = "#b91c1c"
RED_600 = "#dc2626"
RED_500 = "#ef4444"
BLACK = "#000000"
TILE = "#0a0a0a"
INK_DARK = "#f5f5f5"
INK_LIGHT = "#0a0a0a"
MUTED = "#737373"

NAME, PRODUCT = "EYAS", "MCP"
TAGLINE = "MCP SERVER FOR CROWDSTRIKE FALCON"
NAME_TRACKING = 0.18  # em, as in Eyas's Wordmark
TAGLINE_TRACKING = 0.22

# Falcon-A mark on a 32-unit square, as drawn in the Eyas console.
WINGS = [
    [(16, 8), (4, 3), (7, 8), (13, 11)],
    [(16, 8), (29, 1), (25, 7), (19, 11)],
]
LETTER = [
    [(5, 29), (11, 29), (18, 11), (14, 11)],
    [(21, 29), (27, 29), (18, 11), (14, 11)],
    [(13, 11), (19, 11), (16, 6)],
    [(10, 19), (22, 19), (21, 22), (11, 22)],
]
BEAK = [(16, 6), (20, 7), (17, 10)]
GLINT = ((17.5, 7.5), 0.7)


def _d(points) -> str:
    return "M" + " L".join(f"{x:g} {y:g}" for x, y in points) + " Z"


def mark_svg_body(prefix: str) -> str:
    """The mark's SVG elements on the 32-unit grid, with unique gradient ids."""
    (gx, gy), gr = GLINT
    wings = "".join(f'<path d="{_d(p)}" fill="url(#{prefix}-wing)"/>' for p in WINGS)
    letter = "".join(f'<path d="{_d(p)}" fill="url(#{prefix}-a)"/>' for p in LETTER)
    return f"""<defs>
    <linearGradient id="{prefix}-a" x1="0" y1="32" x2="32" y2="0" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{RED_900}"/><stop offset="0.5" stop-color="{RED_600}"/><stop offset="1" stop-color="{RED_500}"/>
    </linearGradient>
    <linearGradient id="{prefix}-wing" x1="0" y1="8" x2="32" y2="2" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{RED_900}"/><stop offset="0.6" stop-color="{RED_600}"/><stop offset="1" stop-color="{RED_500}"/>
    </linearGradient>
  </defs>
  {wings}{letter}<path d="{_d(BEAK)}" fill="{RED_500}"/>
  <circle cx="{gx}" cy="{gy}" r="{gr}" fill="#ffffff" opacity="0.95"/>"""


class Font:
    """Text as SVG outlines at a fixed weight."""

    def __init__(self, path: Path, weight: int):
        font = TTFont(path)
        if "fvar" in font:
            font = instancer.instantiateVariableFont(font, {"wght": weight})
        self.glyphs = font.getGlyphSet()
        self.cmap = font.getBestCmap()
        self.hmtx = font["hmtx"]
        self.upem = font["head"].unitsPerEm

    def _advance(self, char: str) -> int:
        return self.hmtx[self.cmap[ord(char)]][0]

    def width(self, text: str, size: float, tracking: float = 0.0) -> float:
        """Width of the ink run, without tracking after the last letter."""
        units = sum(self._advance(c) for c in text) + tracking * self.upem * (len(text) - 1)
        return units * size / self.upem

    def path(self, text: str, size: float, x: float, baseline: float, tracking: float = 0.0) -> str:
        scale = size / self.upem
        pen = SVGPathPen(self.glyphs)
        for char in text:
            name = self.cmap[ord(char)]
            self.glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
            x += (self.hmtx[name][0] + tracking * self.upem) * scale
        return pen.getCommands()


def logo_svg(sans: Font, mono: Font, ink: str, dark: bool) -> str:
    """Mark beside the EYAS MCP wordmark, with the tagline underneath."""
    mark, size, gap = 128, 72, 36
    x = mark + gap
    name_w = sans.width(NAME, size, NAME_TRACKING)
    space = size * 0.42
    product_x = x + name_w + space
    product_w = sans.width(PRODUCT, size, NAME_TRACKING)
    tag_size = 19.5
    tag_w = mono.width(TAGLINE, tag_size, TAGLINE_TRACKING)
    width = math.ceil(x + max(name_w + space + product_w, tag_w) + 8)
    glow = (
        '<filter id="glow" x="-30%" y="-30%" width="160%" height="160%">'
        f'<feDropShadow dx="0" dy="0" stdDeviation="1.5" flood-color="{RED_600}" flood-opacity="0.55"/>'
        "</filter>"
        if dark
        else ""
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 128" width="{width * 3}" height="384" role="img" aria-label="eyas-mcp">
  <title>eyas-mcp</title>
  <defs>{glow}</defs>
  <g transform="scale(4)"{' filter="url(#glow)"' if dark else ""}>
  {mark_svg_body("logo")}
  </g>
  <path d="{sans.path(NAME, size, x, 74, NAME_TRACKING)}" fill="{ink}"/>
  <path d="{sans.path(PRODUCT, size, product_x, 74, NAME_TRACKING)}" fill="{RED_600}"/>
  <path d="{mono.path(TAGLINE, tag_size, x + 3, 112, TAGLINE_TRACKING)}" fill="{MUTED}"/>
</svg>
"""


def mark_svg() -> str:
    """The app-icon form: the mark on Eyas's rounded black tile."""
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="512" height="512" role="img" aria-label="eyas-mcp">
  <title>eyas-mcp</title>
  <rect width="32" height="32" rx="6" fill="{TILE}"/>
  {mark_svg_body("mark")}
</svg>
"""


# --- Raster versions, drawn with Pillow -------------------------------------------


def _rgb(hex_color: str) -> tuple[int, int, int]:
    return int(hex_color[1:3], 16), int(hex_color[3:5], 16), int(hex_color[5:7], 16)


def _gradient(size: int, start, end, stops) -> Image.Image:
    """Linear gradient across a size x size square, between two points on the 32 grid."""
    (x1, y1), (x2, y2) = start, end
    dx, dy = x2 - x1, y2 - y1
    length = dx * dx + dy * dy
    img = Image.new("RGB", (size, size))
    px = img.load()
    for j in range(size):
        for i in range(size):
            u, v = i * 32 / size, j * 32 / size
            t = max(0.0, min(1.0, ((u - x1) * dx + (v - y1) * dy) / length))
            for (o0, c0), (o1, c1) in zip(stops, stops[1:]):
                if t <= o1:
                    f = (t - o0) / (o1 - o0) if o1 > o0 else 0
                    px[i, j] = tuple(round(a + (b - a) * f) for a, b in zip(_rgb(c0), _rgb(c1)))
                    break
    return img


def draw_mark(size: int, tile: bool) -> Image.Image:
    ss = 4
    big = size * ss
    s = big / 32
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    if tile:
        draw.rounded_rectangle((0, 0, big - 1, big - 1), radius=6 * s, fill=TILE)

    def mask(polys):
        m = Image.new("L", (big, big), 0)
        md = ImageDraw.Draw(m)
        for p in polys:
            md.polygon([(x * s, y * s) for x, y in p], fill=255)
        return m

    letter = _gradient(big, (0, 32), (32, 0), [(0, RED_900), (0.5, RED_600), (1, RED_500)])
    wing = _gradient(big, (0, 8), (32, 2), [(0, RED_900), (0.6, RED_600), (1, RED_500)])
    img.paste(wing, (0, 0), mask(WINGS))
    img.paste(letter, (0, 0), mask(LETTER))
    draw.polygon([(x * s, y * s) for x, y in BEAK], fill=RED_500)
    (gx, gy), gr = GLINT
    draw.ellipse(((gx - gr) * s, (gy - gr) * s, (gx + gr) * s, (gy + gr) * s), fill="#ffffff")
    return img.resize((size, size), Image.LANCZOS)


def _pil_font(path: Path, size: int, weight: int) -> ImageFont.FreeTypeFont:
    font = ImageFont.truetype(str(path), size)
    try:
        font.set_variation_by_axes([weight])
    except OSError:
        pass  # not a variable font
    return font


def _tracked(draw, xy, text, font, fill, tracking, anchor_center=False):
    """Draw letter-spaced text; returns the drawn width."""
    em = font.size
    widths = [draw.textlength(c, font=font) for c in text]
    total = sum(widths) + tracking * em * (len(text) - 1)
    x, y = xy
    if anchor_center:
        x -= total / 2
    for char, w in zip(text, widths):
        draw.text((x, y), char, font=font, fill=fill, anchor="ls")
        x += w + tracking * em
    return total


def social_preview(sans_path: Path, mono_path: Path) -> Image.Image:
    """GitHub's 1280x640 social preview card, laid out like Eyas's banner."""
    w, h = 1280, 640
    img = Image.new("RGB", (w, h), BLACK)

    mark = draw_mark(176, tile=False)
    glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    halo = Image.new("RGBA", mark.size, _rgb(RED_600) + (0,))
    halo.putalpha(mark.getchannel("A").point(lambda a: int(a * 0.8)))
    mx, my = (w - mark.width) // 2, 92
    glow.paste(halo, (mx, my), halo)
    glow = glow.filter(ImageFilter.GaussianBlur(18))
    img.paste(glow, (0, 0), glow)
    img.paste(mark, (mx, my), mark)

    draw = ImageDraw.Draw(img)
    name = _pil_font(sans_path, 104, 800)
    space = 104 * 0.42
    name_w = sum(draw.textlength(c, font=name) for c in NAME) + NAME_TRACKING * 104 * (
        len(NAME) - 1
    )
    prod_w = sum(draw.textlength(c, font=name) for c in PRODUCT) + NAME_TRACKING * 104 * (
        len(PRODUCT) - 1
    )
    x = (w - (name_w + space + prod_w)) / 2
    _tracked(draw, (x, 410), NAME, name, INK_DARK, NAME_TRACKING)
    _tracked(draw, (x + name_w + space, 410), PRODUCT, name, RED_600, NAME_TRACKING)

    mono = _pil_font(mono_path, 24, 500)
    _tracked(draw, (w / 2, 466), TAGLINE, mono, MUTED, TAGLINE_TRACKING, anchor_center=True)
    _tracked(
        draw,
        (w / 2, 506),
        "BUILT ON FALCONPY",
        mono,
        "#525252",
        TAGLINE_TRACKING,
        anchor_center=True,
    )

    small = _pil_font(mono_path, 17, 400)
    _tracked(
        draw,
        (w / 2, h - 44),
        "UNOFFICIAL · NOT AFFILIATED WITH OR ENDORSED BY CROWDSTRIKE, INC.",
        small,
        "#525252",
        0.12,
        anchor_center=True,
    )

    # Sidebar-style hairline: transparent, red, transparent.
    line = Image.new("RGB", (w, 2), _rgb(RED_700))
    fade = Image.new("L", (w, 2))
    fade.putdata([int(255 * math.sin(math.pi * i / (w - 1))) for i in range(w)] * 2)
    img.paste(line, (0, h - 90), fade)
    return img


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sans", type=Path, required=True, help="InterTight[wght].ttf")
    parser.add_argument("--mono", type=Path, required=True, help="JetBrainsMono[wght].ttf")
    args = parser.parse_args()

    ASSETS.mkdir(parents=True, exist_ok=True)
    sans, mono = Font(args.sans, 800), Font(args.mono, 500)
    outputs = {
        "eyas-mcp-logo-light.svg": logo_svg(sans, mono, INK_LIGHT, dark=False),
        "eyas-mcp-logo-dark.svg": logo_svg(sans, mono, INK_DARK, dark=True),
        "eyas-mcp-mark.svg": mark_svg(),
    }
    for name, svg in outputs.items():
        (ASSETS / name).write_text(svg, encoding="utf-8", newline="\n")
    draw_mark(512, tile=True).save(ASSETS / "eyas-mcp-mark.png", optimize=True)
    social_preview(args.sans, args.mono).save(ASSETS / "eyas-mcp-social-preview.png", optimize=True)
    for name in [*outputs, "eyas-mcp-mark.png", "eyas-mcp-social-preview.png"]:
        print(f"wrote docs/assets/{name}")


if __name__ == "__main__":
    main()
