"""Convert the RECON logo's black background to transparent.
Uses max-channel luminance so the cyan glow keeps its soft edges."""
import sys
from pathlib import Path
from PIL import Image
import numpy as np

SRC = Path(r"C:\Users\elias\OneDrive\Desktop\recon logo.png")
DST_PUB = Path(r"C:\Users\elias\Desktop\threat-intel\threat-intel-app\frontend\public\logo.png")
DST_BLD = Path(r"C:\Users\elias\Desktop\threat-intel\threat-intel-app\frontend\build\logo.png")

img = Image.open(SRC).convert("RGBA")
arr = np.array(img)

# Alpha from the brightest of R/G/B — black bg goes to 0, cyan glow stays bright,
# anti-aliased edges keep proportional alpha for a clean cutout.
max_rgb = arr[:, :, :3].max(axis=2)
# Boost: anything brighter than ~12 starts becoming visible; 220+ stays fully opaque.
new_alpha = np.clip((max_rgb.astype(np.int32) - 12) * 255 // 180, 0, 255).astype(np.uint8)
arr[:, :, 3] = new_alpha

out = Image.fromarray(arr, mode="RGBA")
out.save(DST_PUB, optimize=True)
out.save(DST_BLD, optimize=True)
print(f"OK  src={SRC.stat().st_size}  out={DST_PUB.stat().st_size}")
