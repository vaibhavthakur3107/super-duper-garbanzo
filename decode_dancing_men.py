#!/usr/bin/env python3
"""
Dancing Men Cipher Decoder
Decodes the dancing men symbols from the challenge image
"""

from PIL import Image
import numpy as np

# Parse the cipher verses to get the mapping of letters to poses
def parse_cipher_verses():
    """Parse cipher_verses.txt to extract letter-to-pose mappings"""
    with open('cipher_verses.txt', 'r') as f:
        lines = f.readlines()

    # Find and parse each verse
    poses = {}
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line and line[0].isupper():
            # This is a verse line starting with a letter
            letter = line[0]
            # Get the description
            description = line
            # Collect continuation lines
            while i + 1 < len(lines) and lines[i + 1].strip() and not lines[i + 1].strip()[0].isupper():
                i += 1
                if lines[i].strip():
                    description += " " + lines[i].strip()
            poses[letter] = description
        i += 1

    return poses

# Analyze a dancing man figure to determine its pose
def analyze_figure(pixels):
    """
    Analyze a figure's pose based on pixel positions
    Returns a description that can be matched to the cipher verses
    """
    # Find center of the figure
    y_center = pixels[:, 0].mean()
    x_center = pixels[:, 1].mean()

    # Split pixels into upper body and lower body
    upper_mask = pixels[:, 0] < y_center
    lower_mask = pixels[:, 0] >= y_center

    upper_pixels = pixels[upper_mask]
    lower_pixels = pixels[lower_mask]

    # Analyze arm positions from upper body
    # Divide into left and right based on x_center
    left_upper = upper_pixels[upper_pixels[:, 1] < x_center]
    right_upper = upper_pixels[upper_pixels[:, 1] >= x_center]

    # Check for arms going up or down
    left_y_range = left_upper[:, 0].max() - left_upper[:, 0].min() if len(left_upper) > 0 else 0
    right_y_range = right_upper[:, 0].max() - right_upper[:, 0].min() if len(right_upper) > 0 else 0

    # Analyze leg positions from lower body
    left_lower = lower_pixels[lower_pixels[:, 1] < x_center]
    right_lower = lower_pixels[lower_pixels[:, 1] >= x_center]

    # Check if legs are spread
    leg_spread = False
    if len(left_lower) > 0 and len(right_lower) > 0:
        left_x_center = left_lower[:, 1].mean()
        right_x_center = right_lower[:, 1].mean()
        leg_spread = (right_x_center - left_x_center) > (x_center * 0.2)

    # Build a pose signature
    pose = {
        'left_arm': 'UP' if left_upper[:, 0].mean() < y_center - 20 else 'DOWN' if len(left_upper) > 0 else 'NONE',
        'right_arm': 'UP' if right_upper[:, 0].mean() < y_center - 20 else 'DOWN' if len(right_upper) > 0 else 'NONE',
        'leg_spread': leg_spread,
    }

    return pose

def extract_and_decode():
    """Extract all dancing men figures and decode them"""

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

    # Try dividing into 25 sections (reasonable for a message)
    num_divisions = 25
    division_width = width / num_divisions

    figures = []
    for i in range(num_divisions):
        x_start = int(x_min + i * division_width)
        x_end = int(x_min + (i + 1) * division_width)

        # Get pixels in this division
        division_pixels = non_bg_pixels[
            (non_bg_pixels[:, 1] >= x_start) &
            (non_bg_pixels[:, 1] < x_end)
        ]

        if len(division_pixels) > 0:
            figures.append({
                'index': i,
                'pixels': division_pixels,
                'x_range': (x_start, x_end),
            })

    print(f"Found {len(figures)} figures\n")

    # Analyze each figure
    poses = []
    for fig in figures:
        pose = analyze_figure(fig['pixels'])
        poses.append(pose)
        print(f"Figure {fig['index']}: {pose}")

    # Try to match poses to letters
    # For now, let's create a simple signature based on arm positions
    print("\nSimple arm-based decoding:")
    message = ""
    for i, pose in enumerate(poses):
        # Simplified matching based on arm positions
        la = pose['left_arm']
        ra = pose['right_arm']
        ls = pose['leg_spread']

        # This is a heuristic - we need to match against the actual cipher descriptions
        # For now, let's output a simple representation
        symbol = f"[{la}:{ra}:{'S' if ls else 'T'}]"
        message += symbol

    print(f"Message: {message}")

    # Try to output positions more clearly
    print("\nFigure positions and pixel counts:")
    for fig in figures:
        print(f"Figure {fig['index']:2d}: x={fig['x_range'][0]:4d}-{fig['x_range'][1]:4d}, pixels={len(fig['pixels']):5d}")

if __name__ == '__main__':
    extract_and_decode()
