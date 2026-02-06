#!/usr/bin/env python3
"""
Build a complete cipher dictionary from the verses
"""

def build_cipher_dict():
    """Build cipher dictionary mapping pose descriptions to letters"""

    # Manual extraction based on the file structure
    cipher = {
        'A': {
            'left_arm': 'UP',
            'right_arm': 'DOWN',
            'legs': 'TOGETHER',
            'desc': 'Ascending left arm reaches to the SKY, right arm points below, The legs stand firm together'
        },
        'B': {
            'left_arm': 'RIGHT',
            'right_arm': 'DOWN',
            'legs': 'ONE_LEG_UP',
            'desc': 'Balanced stance with left arm pointing RIGHT, while right hangs DOWN, One leg lifts up'
        },
        'C': {
            'left_arm': 'DOWN-LEFT',
            'right_arm': 'UP-RIGHT',
            'legs': 'SPREAD',
            'desc': 'Crossing paths the arms do take - left reaches DOWN and LEFT, While right arm sweeps UP diagonal'
        },
        'D': {
            'left_arm': 'LEFT',
            'right_arm': 'RIGHT',
            'legs': 'TOGETHER',
            'desc': 'Dramatically both arms stretch OUTWARD, LEFT and RIGHT they fly, Horizontal like a crossbeam'
        },
        'E': {
            'left_arm': 'DOWN-LEFT',
            'right_arm': 'UP',
            'legs': 'SPREAD',
            'desc': 'Eagerly the left arm LOW diagonal, while right arm UP does soar, The legs spread wide'
        },
        'F': {
            'left_arm': 'UP',
            'right_arm': 'DOWN-RIGHT',
            'legs': 'TOGETHER',
            'desc': 'Firm the left arm points to SKY, while right slopes DOWN and RIGHT, The legs together'
        },
        'G': {
            'left_arm': 'DOWN-LEFT',
            'right_arm': 'UP-RIGHT',
            'legs': 'SPREAD',
            'desc': 'Gracefully both arms go diagonal - left DOWN-LEFT, right UP-RIGHT, The legs spread'
        },
        'H': {
            'left_arm': 'DOWN',
            'right_arm': 'RIGHT',
            'legs': 'ONE_LEG_UP',
            'desc': 'Halfway right the left arm drops to rest, arm falls to SIX, While right arm stretches SIDEWAYS'
        },
        'I': {
            'left_arm': 'DOWN',
            'right_arm': 'UP',
            'legs': 'SPREAD',
            'desc': 'In this pose the left hangs DOWN, the right reaches UP to noon, Both legs spread apart'
        },
        'J': {
            'left_arm': 'UP-RIGHT',
            'right_arm': 'UP-LEFT',
            'legs': 'SPREAD',
            'desc': 'Joyfully both arms reach UP, forming a V so wide, Diagonal toward the heavens'
        },
        'K': {
            'left_arm': 'UP-LEFT',
            'right_arm': 'DOWN-RIGHT',
            'legs': 'CROSSED',
            'desc': 'Keen the pose: left arm UP-LEFT, right arm DOWN-RIGHT diagonal, The legs cross close together'
        },
        'L': {
            'left_arm': 'LEFT',
            'right_arm': 'NONE',
            'legs': 'TOGETHER',
            'desc': 'Left arm stretches SIDEWAYS out, pointing to NINE on the clock, The other arm stays hidden low'
        },
        'M': {
            'left_arm': 'UP',
            'right_arm': 'RIGHT',
            'legs': 'ONE_LEG_UP',
            'desc': 'Mirrored not from L at all - left arm UP, right arm SIDEWAYS RIGHT, One leg bent'
        },
        'N': {
            'left_arm': 'DOWN-LEFT',
            'right_arm': 'DOWN-RIGHT',
            'legs': 'SPREAD_WIDE',
            'desc': 'Now both arms hang LOW diagonal - DOWN-LEFT and DOWN-RIGHT they fall, The legs spread very WIDE'
        },
        'O': {
            'left_arm': 'DOWN-LEFT',
            'right_arm': 'DOWN',
            'legs': 'TO_SIDE',
            'desc': 'One arm hangs at DOWN-LEFT diagonal, the other straight DOWN below, The legs angle to one side'
        },
        'P': {
            'left_arm': 'UP-RIGHT',
            'right_arm': 'UP',
            'legs': 'SPREAD',
            'desc': 'Pointing UP the left arm climbs to DIAGONAL high, While right arm stretches to the SKY'
        },
        'Q': {
            'left_arm': 'UP',
            'right_arm': 'UP-RIGHT',
            'legs': 'TOGETHER',
            'desc': 'Quite reversed: left arm to SKY, right arm UP-RIGHT diagonal, The legs stand close together'
        },
        'R': {
            'left_arm': 'UP',
            'right_arm': 'DOWN',
            'legs': 'TOGETHER',
            'desc': 'Rising left arm points to SKY, right arm slopes DOWN diagonally, The legs together'
        },
        'S': {
            'left_arm': 'DOWN-LEFT',
            'right_arm': 'UP-RIGHT',
            'legs': 'SPREAD',
            'desc': 'Slanting body tilts to RIGHT, left arm DOWN-LEFT diagonal, Right arm UP-RIGHT'
        },
        'T': {
            'left_arm': 'UP',
            'right_arm': 'UP',
            'legs': 'TOGETHER',
            'desc': 'Two arms raised form a V, both pointing UP toward the sky, The legs stand firm together'
        },
        'U': {
            'left_arm': 'DOWN',
            'right_arm': 'UP-RIGHT',
            'legs': 'SPREAD',
            'desc': 'Under left arm hangs at DOWN, right arm UP-RIGHT diagonal, Both legs spread apart'
        },
        'V': {
            'left_arm': 'DOWN-LEFT',
            'right_arm': 'UP',
            'legs': 'SPREAD',
            'desc': 'Vigorously left arm LOW diagonal, right arm UP to noon, Body tilts with legs spread'
        },
        'W': {
            'left_arm': 'UP-LEFT',
            'right_arm': 'DOWN-RIGHT',
            'legs': 'SPREAD_WIDE',
            'desc': 'Waving left arm UP-LEFT diagonal, right arm DOWN-RIGHT in mirror, The legs spread out'
        },
        'X': {
            'left_arm': 'UP-LEFT',
            'right_arm': 'UP',
            'legs': 'SPREAD',
            'desc': 'eXcited pose with left UP-LEFT, right arm UP to SKY, The body tilts leftward'
        },
        'Y': {
            'left_arm': 'UP',
            'right_arm': 'UP-RIGHT',
            'legs': 'TOGETHER',
            'desc': 'Yearning left arm UP to SKY, right UP-RIGHT diagonal soars, The legs stand close'
        },
        'Z': {
            'left_arm': 'DOWN',
            'right_arm': 'DOWN',
            'legs': 'TOGETHER',
            'desc': 'Zero motion: both arms DOWN, hanging loose at either side, Legs together'
        },
    }

    return cipher

if __name__ == '__main__':
    cipher = build_cipher_dict()
    print(f"Built cipher with {len(cipher)} letters")
    print("\n" + "="*70)
    for letter in sorted(cipher.keys()):
        info = cipher[letter]
        print(f"{letter}: L={info['left_arm']:12s} R={info['right_arm']:12s} Legs={info['legs']:12s}")
