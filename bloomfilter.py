#!/usr/bin/env python
# coding: utf-8

# In[2]:


from helper import (
    bit_field_to_bytes,
    encode_varint,
    int_to_little_endian,
    murmur3,
)
from network import GenericMessage


BIP37_CONSTANT = 0xfba4c795

class BloomFilter:
    
    def __init__(self, size, function_count, tweak):
        self.size = size # in byte
        self.bit_field = [0] * (size * 8)
        self.function_count = function_count
        self.tweak = tweak
        
    def add(self, item):
        '''Add an item to the filter'''
        for i in range(self.function_count):
            seed = i * BIP37_CONSTANT + self.tweak
            hmur = murmur3(item, seed)
            bit = hmur % (self.size * 8)
            self.bit_field[bit] = 1
            
    def filter_bytes(self):
        return bit_field_to_bytes(self.bit_field)
    
    def filterload(self, flag=1):
        command = b'filterload'
        
        payload = encode_varint(self.size)
        payload += self.filter_bytes()
        payload += int_to_little_endian(self.function_count, 4)
        payload += int_to_little_endian(self.tweak, 4)
        payload += int_to_little_endian(flag, 1)
        return GenericMessage(command, payload)


