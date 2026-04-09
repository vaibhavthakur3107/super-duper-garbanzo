#!/usr/bin/env python3
"""
Visualize each dancing man figure as ASCII art
"""

from PIL import Image
import numpy as np

def visualize_figures():
    """Extract and visualize each dancing man figure"""

    # Load image
    img = Image.open('dancing_challenge.png')
    img_array = np.array(img)

    # Background color
    bg_color = (255, 253, 240)

    # Create mask for non-background pixels
    mask = ((img_array[:, :, 0] != bg_color[0]) |
            (img_array[:, :, 1] != bg_color[1]) |
            (img_array[:, :, 2] != bg_color[2]))

    # Get all non-background pixel coordinates
    non_bg_pixels = np.argwhere(mask)

    y_min, y_max = non_bg_pixels[:, 0].min(), non_bg_pixels[:, 0].max()
    x_min, x_max = non_bg_pixels[:, 1].min(), non_bg_pixels[:, 1].max()

    width = x_max - x_min
    height = y_max - y_min

    # Divide into 25 sections
    num_divisions = 25
    division_width = width / num_divisions

    # For each figure, create ASCII art
    for i in range(num_divisions):
        x_start = int(x_min + i * division_width)
        x_end = int(x_min + (i + 1) * division_width)

        # Get pixels in this division
        division_pixels = non_bg_pixels[
            (non_bg_pixels[:, 1] >= x_start) &
            (non_bg_pixels[:, 1] < x_end)
        ]

        if len(division_pixels) == 0:
            continue

        # Normalize coordinates to a small grid
        x_coords = division_pixels[:, 1] - x_start
        y_coords = division_pixels[:, 0] - y_min

        # Create a 20x20 grid
        grid_size = 20
        x_scale = grid_size / (x_end - x_start)
        y_scale = grid_size / height

        grid = [['.' for _ in range(grid_size)] for _ in range(grid_size)]

        for y, x in zip(y_coords, x_coords):
            grid_x = min(int(x * x_scale), grid_size - 1)
            grid_y = min(int(y * y_scale), grid_size - 1)
            grid[grid_y][grid_x] = '#'

        print(f"\nFigure {i}:")
        print("=" * 22)
        for row in grid:
            print(''.join(row))
        print("=" * 22)

        # Analyze the pixel distribution
        print(f"Pixel count: {len(division_pixels)}")

        # Find top, middle, bottom
        y_top = y_coords.min()
        y_bottom = y_coords.max()
        y_middle = y_coords.mean()
        x_left = x_coords.min()
        x_right = x_coords.max()
        x_middle = x_coords.mean()

        print(f"Y range: {y_top:.0f} to {y_bottom:.0f} (middle: {y_middle:.0f})")
        print(f"X range: {x_left:.0f} to {x_right:.0f} (middle: {x_middle:.0f})")

        # Split into top half (arms) and bottom half (legs)
        mid_y = (y_top + y_bottom) / 2
        top_pixels = division_pixels[y_coords < mid_y]
        bottom_pixels = division_pixels[y_coords >= mid_y]

        top_x_coords = top_pixels[:, 1] - x_start
        bottom_x_coords = bottom_pixels[:, 1] - x_start

        if len(top_x_coords) > 0:
            top_left = top_x_coords[top_x_coords < x_middle]
            top_right = top_x_coords[top_x_coords >= x_middle]
            print(f"Top half: {len(top_x_coords)} pixels")
            print(f"  Left side: {len(top_left)} pixels, avg X: {top_left.mean() if len(top_left) > 0 else 0:.1f}")
            print(f"  Right side: {len(top_right)} pixels, avg X: {top_right.mean() if len(top_right) > 0 else 0:.1f}")

        if len(bottom_x_coords) > 0:
            bottom_left = bottom_x_coords[bottom_x_coords < x_middle]
            bottom_right = bottom_x_coords[bottom_x_coords >= x_middle]
            print(f"Bottom half: {len(bottom_x_coords)} pixels")
            print(f"  Left side: {len(bottom_left)} pixels")
            print(f"  Right side: {len(bottom_right)} pixels")

            # Check if legs are spread
            if len(bottom_left) > 0 and len(bottom_right) > 0:
                spread = bottom_right.mean() - bottom_left.mean()
                print(f"  Leg spread: {spread:.1f}")

if __name__ == '__main__':
    visualize_figures()
