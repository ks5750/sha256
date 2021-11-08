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

# #
with open(sys.argv[1]) as json_data:
    inputs = json.load(json_data)
# inputs = json.load(sys.stdin)
outputs = {}

ROUND_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
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


def message_schedule(block):
    assert len(block) == 64
    p5_inputWords=[]
    for x in range(0, len(block), 4):
        p5_inputWords.append(int.from_bytes(block[x:x + 4], "big"))

    for y in range(16, len(block)):
        p5_inputWords.append(add32(add32(p5_inputWords[y-16] ,little_sigma0(p5_inputWords[y-15])),
                                   add32(p5_inputWords[y-7] ,little_sigma1(p5_inputWords[y-2]))))

    return p5_inputWords

def big_sigma0(x):
    return rightrotate32(x, 2) ^ rightrotate32(x, 13) ^ rightrotate32(x, 22)

def big_sigma1(x):
    return rightrotate32(x, 6) ^ rightrotate32(x, 11) ^ rightrotate32(x, 25)

def choice(x,y,z):
    return (x & y) ^ (~x & z)

def majority(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)

def round(state, round_constant, schedule_word):

    ch = choice(state[4], state[5], state[6])
    temp1 = add32( add32( add32(state[7] , big_sigma1(state[4])), add32(ch, round_constant)), schedule_word)
    maj = majority(state[0], state[1], state[2])
    temp2 = add32(big_sigma0(state[0]) , maj)

    new_state=[add32(temp1 ,temp2),state[0],
    state[1],
    state[2],
    add32( state[3] , temp1),
    state[4],
    state[5],
    state[6],
    ]
    return new_state

def compress(input_state, block):
    assert len(block) == 64
    W = message_schedule(block)
    state = input_state
    for i in range(0,64):
        state = round(state, ROUND_CONSTANTS[i], W[i])

    state = [
        add32( input_state[0] , state[0]),
        add32( input_state[1] , state[1]),
        add32( input_state[2] , state[2]),
        add32( input_state[3] , state[3]),
        add32( input_state[4] , state[4]),
        add32( input_state[5] , state[5]),
        add32( input_state[6] , state[6]),
        add32( input_state[7] , state[7]),
    ]


    return state

IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
def padding(message_length):
    remainder_bytes = (message_length + 8) % 64  # number of bytes in the final block, including the appended length
    filler_bytes = 64 - remainder_bytes  # number of bytes we need to add, including the initial 0x80 byte
    zero_bytes = filler_bytes - 1  # number of 0x00 bytes we need to add

    pad_byteString= '80'
    finalString=pad_byteString + zero_bytes*"00" + str((8 * message_length).to_bytes(8, "big").hex())

    return finalString


def sha256(message):

    padd =padding(len(message))
    # padMessage=bytes.fromhex(padd)+bytes(message,'utf-8')
    padMessage=bytes(message,'utf-8')+bytes.fromhex(padd)
    state =IV
    shaFinal=""
    for i in range(0, len(padMessage),64):
        # print(padMessage[i:i+64].hex())
        block=padMessage[i:i+64]
        state=compress(state,block)
    # print("state-->",state)

    for i in state:
       shaFinal =shaFinal+i.to_bytes(4, "big").hex()

    return shaFinal


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
lilSigma3=little_sigma0(p3_input)
outputs["problem3"] = lilSigma3

# Problem 4
p4_input = inputs["problem4"]
lilSigma4=little_sigma1(p4_input)
outputs["problem4"] = lilSigma4


# Problem 5
p5_input = inputs["problem5"]
outputs["problem5"] =message_schedule(p5_input.encode())

# Problem 6
p6_input = inputs["problem6"]
outputs["problem6"] =big_sigma0(p6_input)

# Problem 7
p7_input = inputs["problem7"]
outputs["problem7"] =big_sigma1(p7_input)



# Problem 8
p8_input = inputs["problem8"]
outputs["problem8"] =choice(p8_input[0],p8_input[1],p8_input[2])

# Problem 9
p9_input = inputs["problem9"]
outputs["problem9"] =majority(p9_input[0],p9_input[1],p9_input[2])

# Problem 10
p10_input = inputs["problem10"]

state=p10_input["state"]
round_constant=p10_input["round_constant"]
schedule_word=p10_input["schedule_word"]
outputs["problem10"] =round(state,round_constant,schedule_word)

# Problem 11
p11_input = inputs["problem11"]

state=p11_input["state"]
block=p11_input["block"]
outputs["problem11"] =compress (state,block.encode())

# Problem 12
p12_input = inputs["problem12"]
p12_output=[]
for x in p12_input:
    p12_output.append(padding(x))
outputs["problem12"] =p12_output


# Problem 13
p13_input = inputs["problem13"]
p13_output=[]
for x in p13_input:
    p13_output.append(sha256(x))
outputs["problem13"] =p13_output


# Problem 14
p14_input = inputs["problem14"]
original_in = p14_input["original_input"]
original_input = p14_input["original_input"].encode().hex()
chosen_suffix = p14_input["chosen_suffix"].encode().hex()
padd14=padding(len(original_in))
final=original_input+padd14+chosen_suffix
outputs["problem14"] =final


# Problem 15
p15_input = bytes.fromhex(inputs["problem15"])
final15=[]
for i in range(0, len(p15_input),4):
    final15.append(int.from_bytes(p15_input[i:i+4], "big"))
outputs["problem15"] =final15


# Problem 16
p16_input = inputs["problem16"]
original_hash=bytes.fromhex(p16_input["original_hash"])
original_len=p16_input["original_len"]
stateWords=[]
chosen_suffix=bytes(p16_input["chosen_suffix"],'ASCII')

for i in range(0, len(original_hash),4):
    stateWords.append(int.from_bytes(original_hash[i:i+4], "big"))

pad_original=padding(original_len)
syntheticMesg= original_len+len(pad_original)+len(p16_input["chosen_suffix"].encode())

newPadding=padding(syntheticMesg)
paddedSuffix=chosen_suffix+newPadding.encode()

# for i in range(paddedSuffix):
#     compress()

print("syntheticMesg lentgh ",syntheticMesg)

# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
# print(json.dumps(outputs, indent="  "))
