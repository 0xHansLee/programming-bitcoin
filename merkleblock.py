#!/usr/bin/env python
# coding: utf-8

# In[6]:


import math

from io import BytesIO

from helper import (
    bytes_to_bit_field,
    little_endian_to_int,
    merkle_parent,
    read_varint,
)

class MerkleTree:
    
    def __init__(self, total):
        self.total = total
        self.max_depth = math.ceil(math.log(self.total, 2))
        self.nodes = []
        for depth in range(self.max_depth + 1):
            level_hashes = [None] * (2**depth)
            self.nodes.append(level_hashes)
        self.current_depth = 0
        self.current_index = 0
        
    def __repr__(self):
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                if h is None:
                    short = 'None'
                else:
                    short = f'{h.hex()[:8]}...'
                if depth == self.current_depth and index == self.current_index:
                    items.append(f'*{short[:-2]}*')
                else:
                    items.append(f'{short}')
            result.append(', '.join(items))
        return '\n'.join(result)
    
    def up(self):
        self.current_depth -= 1
        self.current_index //=2
        
    def left(self):
        self.current_depth += 1
        self.current_index *= 2
        
    def right(self):
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1
    
    def root(self):
        return self.nodes[0][0]
    
    def set_current_node(self, value):
        self.nodes[self.current_depth][self.current_index] = value
        
    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_index]
    
    def get_left_node(self):
        return self.nodes[self.current_depth + 1][self.currnet_index * 2]
    
    def get_right_node(self):
        return self.nodes[self.current_depth + 1][self.currnet_index * 2 + 1]
    
    def is_leaf(self):
        return self.current_depth == self.max_depth
    
    def right_exists(self):
        return len(self.nodes[self.current_depth + 1]) > self.currnet_index * 2 + 1
    
    def populate_tree(self, flag_bits, hashes):
        while self.root() is None:
            if self.is_leaf():
                flag_bits.pop(0)
                self.set_current_node(hashes.pop(0))
                self.up()
            else:
                left_hash = self.get_left_node()
                if left_hash is None:
                    if flag_bits.pop(0) == 0: # pre-calculated hash
                        self.set_current_node(hashes.pop(0))
                        self.up()
                    else:
                        self.left()
                elif self.right_exists():
                    right_hash = self.get_right_node()
                    if right_hash is None:
                        self.right()
                    else:
                        self.set_current_node(merkle_parent(left_hash, right_hash))
                        self.up()
                else:
                    self.set_current_node(merkle_parent(left_hash, left_hash))
                    self.up()
        if len(hashes) != 0:
            raise RuntimeError(f'hashes not all consumed {len(hashes)}')
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError('flag bits not all consumed')
                

class MerkleBlock:
    command = b'merkleblock'
    
    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.total = total
        self.hashes = hashes
        self.flags = flags
        
    def __repr__(self):
        result = f'{self.total}'
        for h in self.hashes:
            result += f'\t{h.hex()}\n'
        result += f'self.flags.hex()'
        
    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        total = little_endian_to_int(s.read(4))
        num_hashes = read_varint(s)
        hashes = []
        for _ in range(num_hashes):
            hashes.append(s.read(32)[::-1])
        flags_length = read_varint(s)
        flags = s.read(flags_length)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags)
        
    def is_valid(self):
        mktree = MerkleTree(self.total)
        flag_bits = bytes_to_bit_field(self.flags)
        hashes = [h[::-1] for h in self.hashes]
        mktree.populate_tree(flag_bits, hashes)
        return self.merkle_root == mktree.root()[::-1]
        


# In[11]:



from helper import merkle_parent_level
hex_hashes = [
    "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
    "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
    "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
    "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
    "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
    "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
    "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
    "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
    "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
    "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
    "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
    "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
    "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
    "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
    "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
    "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
]
tree = MerkleTree(len(hex_hashes))
tree.nodes[4] = [bytes.fromhex(h) for h in hex_hashes]
tree.nodes[3] = merkle_parent_level(tree.nodes[4])
tree.nodes[2] = merkle_parent_level(tree.nodes[3])
tree.nodes[1] = merkle_parent_level(tree.nodes[2])
tree.nodes[0] = merkle_parent_level(tree.nodes[1])
print(tree)


# In[ ]:




