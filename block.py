#!/usr/bin/env python
# coding: utf-8

# In[1]:


from helper import hash256, bits_to_target, little_endian_to_int, int_to_little_endian

GENESIS_BLOCK = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
TESTNET_GENESIS_BLOCK = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
LOWEST_BITS = bytes.fromhex('ffff001d')

class Block:
    
    def __init__(self, version, prev_block_hash, merkle_root, timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes
        
    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block_hash = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block_hash, merkle_root, timestamp, bits, nonce)
    
    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block_hash[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result
    
    def hash256(self):
        h256 = hash256(self.serialize())
        return h256[::-1]
    
    def bip9(self):
        return self.version >> 29 == 0b001
    
    def bip91(self):
        return self.version >> 4 & 1 == 1
    
    def bip141(self):
        return self.version >> 1 & 1 == 1

    def target(self):
        return bits_to_target(self.bits)
    
    def difficulty(self):
        lowest = 0xffff * 256 ** (0x1d - 3)
        return lowest / self.target()
    
    def check_pow(self):
        h256 = hash256(self.serialize())
        return little_endian_to_int(h256) < self.target()
    
    def validate_merkle_root(self):
        hashes = [h[::-1] for h in self.tx_hashes]
        root = merkle_root(hashes)[::-1]
        return root == self.merkle_root

