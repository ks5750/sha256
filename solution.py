#! /usr/bin/env python3

import cryptography
import nacl.secret
from nacl.secret import SecretBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import sys
import json
import secrets
import hashlib

#
# with open(sys.argv[1]) as json_data:
#   inputs = json.load(json_data)
inputs = json.load(sys.stdin)
outputs = {}


#
def add32(x, y):
    modVal = (x + y) % 2 ** 32
    return modVal

def rightrotate32(x, n):
    assert x < 2 ** 32, "x is too large. Did you use + instead of add32 somewhere?"
    right_part = x >> n
    left_part = (x << (32 - n)) % (2 ** 32)
    return left_part | right_part

def little_sigma0(x):
    return rightrotate32(x, 7) ^ rightrotate32(x, 18) ^ (x >> 3)

def little_sigma1(x):
    return rightrotate32(x, 17) ^ rightrotate32(x, 19) ^ (x >> 10)


# Problem 1
p1_input = inputs["problem1"]
p1_array = []

for x in p1_input:
    modVal = add32(x[0], x[1])
    p1_array.append(modVal)
outputs["problem1"] = p1_array

# Problem 2
p2_input = inputs["problem2"]
p2_array = []
for x in p2_input:
    val = rightrotate32(x[0], x[1])
    p2_array.append(val)
outputs["problem2"] = p2_array

# Problem 3
p3_input = inputs["problem3"]
lilSigma3=rightrotate32(p3_input, 7) ^ rightrotate32(p3_input, 18) ^ (p3_input >> 3)
outputs["problem3"] = lilSigma3

# Problem 4
p4_input = inputs["problem4"]
lilSigma4=rightrotate32(p4_input, 7) ^ rightrotate32(p4_input, 18) ^ (p4_input >> 3)
outputs["problem4"] = lilSigma4


# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
