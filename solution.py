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
with open(sys.argv[1]) as json_data:
  inputs = json.load(json_data)
# inputs = json.load(sys.stdin)
outputs = {}

#
def add32(x,y):

    modVal = (x+y) % 2 ** 32
    return modVal

# Problem 1
p1_input = inputs["problem1"]
p1_array=[]

for x in p1_input:
    modVal= add32(x[0],x[1])
    p1_array.append(modVal)
outputs["problem1"]=p1_array
# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
