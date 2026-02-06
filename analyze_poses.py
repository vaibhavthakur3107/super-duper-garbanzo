#!/usr/bin/env python3
"""
Analyze dancing men poses more carefully
"""

from PIL import Image
import numpy as np

def analyze_pose_detailed(pixels, division_index):
    """Detailed analysis of a figure's pose"""

    # Find bounds
    y_min, y_max = pixels[:, 0].min(), pixels[:, 0].max()
    x_min, x_max = pixels[:, 1].min(), pixels[:, 1].max()

    y_center = y_min + (y_max - y_min) / 2
    x_center = x_min + (x_max - x_min) / 2
    y_quarter = y_min + (y_max - y_min) / 4

    # Split into regions
    # Top-left, top-right for arms
    # Bottom-left, bottom-right for legs
    top_left = pixels[(pixels[:, 0] < y_center) & (pixels[:, 1] < x_center)]
    top_right = pixels[(pixels[:, 0] < y_center) & (pixels[:, 1] >= x_center)]
    bottom_left = pixels[(pixels[:, 0] >= y_center) & (pixels[:, 1] < x_center)]
    bottom_right = pixels[(pixels[:, 0] >= y_center) & (pixels[:, 1] >= x_center)]

    # Check arm directions by looking at pixel distribution in top half
    left_arm_pixels = top_left
    right_arm_pixels = top_right

    # Analyze left arm
    if len(left_arm_pixels) > 0:
        left_arm_y_mean = left_arm_pixels[:, 0].mean()
        left_arm_x_mean = left_arm_pixels[:, 1].mean()
        # Compare to center of top-left quadrant
        left_center_y = y_min + (y_center - y_min) / 2
        left_center_x = x_min + (x_center - x_min) / 2

        if left_arm_y_mean < left_center_y - (y_center - y_min) * 0.3:
            left_arm = "UP"
        elif left_arm_x_mean < x_min + (x_center - x_min) * 0.3:
            left_arm = "LEFT"
        elif left_arm_x_mean > x_center - (x_center - x_min) * 0.3:
            left_arm = "RIGHT"
        elif left_arm_y_mean > y_center - (y_center - y_min) * 0.3:
            left_arm = "DOWN"
        elif left_arm_y_mean < left_center_y and left_arm_x_mean < left_center_x:
            left_arm = "UP-LEFT"
        elif left_arm_y_mean < left_center_y and left_arm_x_mean > left_center_x:
            left_arm = "UP-RIGHT"
        elif left_arm_y_mean > left_center_y and left_arm_x_mean < left_center_x:
            left_arm = "DOWN-LEFT"
        elif left_arm_y_mean > left_center_y and left_arm_x_mean > left_center_x:
            left_arm = "DOWN-RIGHT"
        else:
            left_arm = "UNKNOWN"
    else:
        left_arm = "NONE"

    # Analyze right arm
    if len(right_arm_pixels) > 0:
        right_arm_y_mean = right_arm_pixels[:, 0].mean()
        right_arm_x_mean = right_arm_pixels[:, 1].mean()
        right_center_y = y_min + (y_center - y_min) / 2
        right_center_x = x_center + (x_max - x_center) / 2

        if right_arm_y_mean < right_center_y - (y_center - y_min) * 0.3:
            right_arm = "UP"
        elif right_arm_x_mean < x_center + (x_max - x_center) * 0.3:
            right_arm = "LEFT"
        elif right_arm_x_mean > x_max - (x_max - x_center) * 0.3:
            right_arm = "RIGHT"
        elif right_arm_y_mean > y_center - (y_center - y_min) * 0.3:
            right_arm = "DOWN"
        elif right_arm_y_mean < right_center_y and right_arm_x_mean < right_center_x:
            right_arm = "UP-LEFT"
        elif right_arm_y_mean < right_center_y and right_arm_x_mean > right_center_x:
            right_arm = "UP-RIGHT"
        elif right_arm_y_mean > right_center_y and right_arm_x_mean < right_center_x:
            right_arm = "DOWN-LEFT"
        elif right_arm_y_mean > right_center_y and right_arm_x_mean > right_center_x:
            right_arm = "DOWN-RIGHT"
        else:
            right_arm = "UNKNOWN"
    else:
        right_arm = "NONE"

    # Analyze legs
    if len(bottom_left) > 0 and len(bottom_right) > 0:
        left_leg_x = bottom_left[:, 1].mean()
        right_leg_x = bottom_right[:, 1].mean()
        spread = right_leg_x - left_leg_x
        # Normalize spread relative to width
        width = x_max - x_min
        if spread > width * 0.4:
            legs = "SPREAD_WIDE"
        elif spread > width * 0.2:
            legs = "SPREAD"
        else:
            legs = "TOGETHER"
    elif len(bottom_left) > 0:
        legs = "TO_LEFT"
    elif len(bottom_right) > 0:
        legs = "TO_RIGHT"
    else:
        legs = "UNKNOWN"

    # Body tilt - compare body mass distribution
    total_mass = len(pixels)
    left_mass = len(pixels[pixels[:, 1] < x_center])
    right_mass = len(pixels[pixels[:, 1] >= x_center])

    if abs(left_mass - right_mass) > total_mass * 0.15:
        tilt = "LEFT" if left_mass > right_mass else "RIGHT"
    else:
        tilt = "CENTER"

    return {
        'left_arm': left_arm,
        'right_arm': right_arm,
        'legs': legs,
        'tilt': tilt,
        'left_mass': left_mass,
        'right_mass': right_mass,
    }

def decode_all():
    """Decode all figures"""

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

    poses = []
    for i in range(num_divisions):
        x_start = int(x_min + i * division_width)
        x_end = int(x_min + (i + 1) * division_width)

        division_pixels = non_bg_pixels[
            (non_bg_pixels[:, 1] >= x_start) &
            (non_bg_pixels[:, 1] < x_end)
        ]

        if len(division_pixels) > 0:
            pose = analyze_pose_detailed(division_pixels, i)
            poses.append((i, pose))
            print(f"Figure {i:2d}: L={pose['left_arm']:12s} R={pose['right_arm']:12s} Legs={pose['legs']:12s} Tilt={pose['tilt']:6s}")

    return poses

if __name__ == '__main__':
    decode_all()
