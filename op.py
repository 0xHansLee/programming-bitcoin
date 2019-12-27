#!/usr/bin/env python
# coding: utf-8

# In[59]:


import hashlib
from helper import (
    hash160,
    hash256,
)

from ecc import (
    S256Point,
    Signature,
)

def encode_num(num):
    if num == 0:
        return b''
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xff) # append 8 bits in little endian
        abs_num >>= 8
    if result[-1] & 0x80: # The most significant bit is 1
        if negative:
            result.append(0x80) # if negative, add 0x80 (neg)
        else:
            result.append(0) # else, add 0
    elif negative: # if negative, change the most significant bit to 1
        result[-1] |= 0x80
    return bytes(result)
        
def decode_num(element):
    if element == b'':
        return 0
    big_endian = element[::-1]
    if big_endian[0] & 0x80: # check the most significant bit
        negative = True
        result = big_endian[0] & 0x7f # compare with 0x01111111
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8 # in little endian
        result += c
    return -result if negative else result

def op_0(stack):
    stack.append(encode_num(0))
    return True

def op_dup(stack):
    if len(stack) < 0:
        return False
    stack.append(stack[-1])
    return True

def op_hash256(stack):
    if len(stack) < 0:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True

def op_hash160(stack):
    if len(stack) < 0:
        return False
    element = stack.pop()
    stack.append(hash160(element))
    return True

def op_checksig(stack, z):
    if len(stack) < 2:
        return False
    pub_sec = stack.pop()
    sig_der = stack.pop()[:-1] # except hash_type
    try:
        pub_point = S256Point.parse(pub_sec)
        sig = Signature.parse(sig_der)
    except (ValueError, SyntaxError) as e:
        return False
    if pub_point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True

def op_equal(stack):
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True

def op_verify(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True

def op_equalverify(stack):
    return op_equal(stack) and op_verify(stack)
    
def op_checkmultisig(stack, z):
    # m of n multi-sig
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n+1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m+1:
        return False
    der_signatures = []
    for _ in range(m):
        der_signatures.append(stack.pop()[:-1])
    stack.pop() # Off-by-One bug
    try:
        pubPoints = [S256Point.parse(sec) for sec in sec_pubkeys]
        sigs = [Signature.parse(der) for der in der_signatures]
        for sig in sigs:
            if len(pubPoints) == 0:
                return False
            while pubPoints:
                pubPoint = pubPoints.pop(0)
                if pubPoint.verify(z, sig):
                    break
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


OP_CODE_FUNCTIONS = {
    0: op_0,
    105: op_verify,
    118: op_dup,
    135: op_equal,
    136: op_equalverify,
    169: op_hash160,
    170: op_hash256,
    172: op_checksig,
}

OP_CODE_NAMES = {
    0: 'OP_0',
    105: 'OP_VERIFY',
    118: 'OP_DUP',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    172: 'OP_CHECKSIG',
}

