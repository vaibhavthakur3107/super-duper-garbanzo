#!/usr/bin/env python3
"""
Extract each dancing man figure as a separate image
"""

from PIL import Image, ImageDraw
import numpy as np
import os

def extract_figures():
    """Extract each figure as a separate image"""

    # Load image
    img = Image.open('dancing_challenge.png')
    img_array = np.array(img)

    # Background color
    bg_color = (255, 253, 240)

    # Create mask for non-background pixels
    mask = ((img_array[:, :, 0] != bg_color[0]) |
            (img_array[:, :, 1] != bg_color[1]) |
            (img_array[:, :, 2] != bg_color[2]))

    non_bg_pixels = np.argwhere(mask)

    y_min, y_max = non_bg_pixels[:, 0].min(), non_bg_pixels[:, 0].max()
    x_min, x_max = non_bg_pixels[:, 1].min(), non_bg_pixels[:, 1].max()

    width = x_max - x_min
    height = y_max - y_min
    num_divisions = 25
    division_width = width / num_divisions

    # Create output directory
    os.makedirs('figures', exist_ok=True)

    # Extract each figure
    for i in range(num_divisions):
        x_start = int(x_min + i * division_width)
        x_end = int(x_min + (i + 1) * division_width)

        # Get pixels in this division
        division_mask = mask[y_min:y_max, x_start:x_end]
        division_img = img_array[y_min:y_max, x_start:x_end]

        # Create a new image with just this figure
        new_img = Image.fromarray(division_img.astype(np.uint8))

        # Save it
        new_img.save(f'figures/figure_{i:02d}.png')
        print(f"Saved figure {i}")

    print(f"\nExtracted {num_divisions} figures to 'figures/' directory")

if __name__ == '__main__':
    extract_figures()
