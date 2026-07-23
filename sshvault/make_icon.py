#!/usr/bin/env python3
"""Generate SSHVault icon — dark terminal aesthetic with a lock + >_ symbol."""

from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

SIZE = 256
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# ── background rounded rect ──────────────────────────────────────────────────
BG = (30, 30, 46, 255)  # #1e1e2e
ACCENT = (122, 162, 247, 255)  # #7aa2f7
GREEN = (158, 206, 106, 255)  # #9ece6a
YELLOW = (224, 175, 104, 255)  # #e0af68
RED = (247, 118, 142, 255)  # #f7768e
TEXT = (205, 214, 244, 255)  # #cdd6f4
PANEL = (42, 42, 62, 255)  # #2a2a3e

R = 44  # corner radius


def rounded_rect(draw, xy, radius, fill):
    x0, y0, x1, y1 = xy
    r = min(radius, (x1 - x0) // 2, (y1 - y0) // 2)
    if x0 + r < x1 - r:
        draw.rectangle([x0 + r, y0, x1 - r, y1], fill=fill)
    if y0 + r < y1 - r:
        draw.rectangle([x0, y0 + r, x1, y1 - r], fill=fill)
    draw.ellipse([x0, y0, x0 + 2 * r, y0 + 2 * r], fill=fill)
    draw.ellipse([x1 - 2 * r, y0, x1, y0 + 2 * r], fill=fill)
    draw.ellipse([x0, y1 - 2 * r, x0 + 2 * r, y1], fill=fill)
    draw.ellipse([x1 - 2 * r, y1 - 2 * r, x1, y1], fill=fill)


# outer shadow (fake drop shadow)
for offset in range(6, 0, -1):
    alpha = int(180 * (1 - offset / 7))
    shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    rounded_rect(sd, (offset + 8, offset + 8, SIZE - 8 + offset, SIZE - 8 + offset), R, (0, 0, 0, alpha))
    img = Image.alpha_composite(img, shadow)
    draw = ImageDraw.Draw(img)

# main background
rounded_rect(draw, (8, 8, SIZE - 8, SIZE - 8), R, BG)

# top bar strip (like a terminal title bar)
bar_h = 44
rounded_rect(draw, (8, 8, SIZE - 8, 8 + bar_h), R, PANEL)
draw.rectangle([8, 8 + R, SIZE - 8, 8 + bar_h], fill=PANEL)

# traffic-light dots in title bar
for i, color in enumerate([RED, YELLOW, GREEN]):
    cx = 30 + i * 22
    cy = 8 + bar_h // 2
    r = 7
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)

# ── terminal prompt  >_  ─────────────────────────────────────────────────────
# Draw using geometric shapes (no font dependency)

cx, cy = SIZE // 2, SIZE // 2 + 24

# ">" chevron
pts_chevron = [
    (cx - 52, cy - 30),
    (cx - 18, cy),
    (cx - 52, cy + 30),
]
# draw thick chevron as filled polygon + anti-alias via lines
thick = 10
for dx in range(-1, 2):
    for dy in range(-1, 2):
        shifted = [(x + dx, y + dy) for x, y in pts_chevron]
        draw.line(shifted[:2], fill=GREEN, width=thick)
        draw.line(shifted[1:], fill=GREEN, width=thick)

# "_" underscore cursor
ux0 = cx - 8
ux1 = cx + 52
uy = cy + 30
draw.rectangle([ux0, uy - 5, ux1, uy + 3], fill=ACCENT)

# ── lock shackle (top-right area) ────────────────────────────────────────────
lx, ly = SIZE - 58, 68
lw, lh = 36, 32
shackle_r = 14
# shackle arc
draw.arc([lx + 4, ly - shackle_r - 4, lx + lw - 4, ly + shackle_r], start=180, end=0, fill=YELLOW, width=7)
# lock body
body_top = ly + 8
draw.rounded_rectangle([lx, body_top, lx + lw, body_top + lh], radius=6, fill=YELLOW)
# keyhole
kx, ky = lx + lw // 2, body_top + 11
draw.ellipse([kx - 5, ky - 5, kx + 5, ky + 5], fill=BG)
draw.rectangle([kx - 3, ky, kx + 3, ky + 10], fill=BG)

# ── "SSHVault" text at bottom ────────────────────────────────────────────────
# draw letter-by-letter using tiny rectangles (pixel font style)
# Simple approach: use PIL default font and draw text
try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22)
except Exception:
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", 22)
    except Exception:
        font = ImageFont.load_default()

label = "SSHVault"
bbox = draw.textbbox((0, 0), label, font=font)
tw = bbox[2] - bbox[0]
tx = (SIZE - tw) // 2
ty = SIZE - 42
draw.text((tx + 1, ty + 1), label, font=font, fill=(0, 0, 0, 160))
draw.text((tx, ty), label, font=font, fill=TEXT)

# save beside this script; never depend on a developer's checkout path
output_dir = Path(__file__).resolve().parent
out = output_dir / "sshvault-icon.png"
img.save(out, "PNG")

# also save multiple sizes for .ico
sizes = [16, 32, 48, 64, 128, 256]
imgs = [img.resize((s, s), Image.LANCZOS) for s in sizes]
imgs[0].save(
    output_dir / "sshvault.ico",
    format="ICO",
    sizes=[(s, s) for s in sizes],
    append_images=imgs[1:],
)

print(f"Icon saved: {out}")
print(f"ICO saved:  {output_dir / 'sshvault.ico'}")
