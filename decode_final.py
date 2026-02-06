#!/usr/bin/env python3
"""
Final decoder - match detected poses to cipher using fuzzy matching
"""

from PIL import Image
import numpy as np
from build_cipher_dict import build_cipher_dict

def extract_features(pixels):
    """Extract simple features from a figure"""

    y_min, y_max = pixels[:, 0].min(), pixels[:, 0].max()
    x_min, x_max = pixels[:, 1].min(), pixels[:, 1].max()

    y_center = y_min + (y_max - y_min) / 2
    x_center = x_min + (x_max - x_min) / 2

    # Divide into quadrants
    top_left = pixels[(pixels[:, 0] < y_center) & (pixels[:, 1] < x_center)]
    top_right = pixels[(pixels[:, 0] < y_center) & (pixels[:, 1] >= x_center)]
    bottom_left = pixels[(pixels[:, 0] >= y_center) & (pixels[:, 1] < x_center)]
    bottom_right = pixels[(pixels[:, 0] >= y_center) & (pixels[:, 1] >= x_center)]

    total = len(pixels)

    features = {
        'tl_ratio': len(top_left) / total,
        'tr_ratio': len(top_right) / total,
        'bl_ratio': len(bottom_left) / total,
        'br_ratio': len(bottom_right) / total,
    }

    return features

def match_pose(features, cipher):
    """Find the best matching letter for the detected features"""

    best_match = None
    best_score = 999

    for letter, pose in cipher.items():
        # Calculate a simple score based on pose description
        score = 0

        left_arm = pose['left_arm']
        right_arm = pose['right_arm']
        legs = pose['legs']

        # Check leg spread
        if legs == 'SPREAD_WIDE' or legs == 'SPREAD':
            score += 0
        elif legs == 'TOGETHER':
            score += 5
        else:
            score += 3

        # Check arms
        if left_arm == 'UP' and right_arm == 'UP':
            score += 0  # Matched
        elif 'UP' in left_arm and 'UP' in right_arm:
            score += 2  # Partial match
        elif left_arm == 'DOWN' and right_arm == 'DOWN':
            score += 10
        elif left_arm == 'UP' and right_arm == 'DOWN':
            score += 3
        elif left_arm == 'DOWN' and right_arm == 'UP':
            score += 3
        elif 'UP-LEFT' in left_arm and 'UP-RIGHT' in right_arm:
            score += 0
        elif 'UP-LEFT' in left_arm or 'UP-RIGHT' in right_arm:
            score += 2
        else:
            score += 5

        if score < best_score:
            best_score = score
            best_match = letter

    return best_match, best_score

def decode_message():
    """Decode the complete message"""

    # Load cipher
    cipher = build_cipher_dict()

    # Load image
    img = Image.open('dancing_challenge.png')
    img_array = np.array(img)

    # Background color
    bg_color = (255, 253, 240)

    # Create mask
    mask = ((img_array[:, :, 0] != bg_color[0]) |
            (img_array[:, :, 1] != bg_color[1]) |
            (img_array[:, :, 2] != bg_color[2]))

    non_bg_pixels = np.argwhere(mask)

    y_min, y_max = non_bg_pixels[:, 0].min(), non_bg_pixels[:, 0].max()
    x_min, x_max = non_bg_pixels[:, 1].min(), non_bg_pixels[:, 1].max()

    width = x_max - x_min
    num_divisions = 25
    division_width = width / num_divisions

    message = ""
    print("Decoding figures:")
    print("="*70)

    for i in range(num_divisions):
        x_start = int(x_min + i * division_width)
        x_end = int(x_min + (i + 1) * division_width)

        division_pixels = non_bg_pixels[
            (non_bg_pixels[:, 1] >= x_start) &
            (non_bg_pixels[:, 1] < x_end)
        ]

        if len(division_pixels) == 0:
            continue

        features = extract_features(division_pixels)
        letter, score = match_pose(features, cipher)

        message += letter
        print(f"Figure {i:2d}: {letter} (score: {score}) - TL={features['tl_ratio']:.2f} TR={features['tr_ratio']:.2f} BL={features['bl_ratio']:.2f} BR={features['br_ratio']:.2f}")

    print("\n" + "="*70)
    print(f"Decoded message: {message}")
    return message

if __name__ == '__main__':
    message = decode_message()
