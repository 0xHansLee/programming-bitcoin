
from helper import (
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    encode_varint,
    SIGHASH_ALL,
)
from io import BytesIO
import json
import requests
from script import script
from ecc import PrivateKey

# Transaction class (version, inputs, outputs, locktime)
class Tx:
    
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        
    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
            
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        
        return f'tx : {self.id()}\nversion : {self.version}\ntx inputs : \n{tx_ins}tx outputs : \n{tx_outs}locktime : {self.locktime}'
    
    def id(self):
        '''Transaction hash in hexadecimal'''
        return self.hash().hex()
    
    def hash(self):
        '''Binary hash of the legacy serialization'''
        return hash256(self.serialize())[::-1]
    
    @classmethod
    def parse(cls, s, testnet=False):
        version = little_endian_to_int(s.read(4))
        
        n_inputs = read_varint(s)
        inputs = []
        for _ in range(n_inputs):
            inputs.append(TxInput.parse(s))
        
        n_outputs = read_varint(s)
        outputs = []
        for _ in range(n_outputs):
            outputs.append(TxOutput.parse(s))
            
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet)
        
    def serialize(self):
        '''Returns the byte serialize of the Tx'''
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result
    
    def fee(self, testnet=False):
        '''Calculate fee'''
        total_in_value = 0
        for tx_in in self.tx_ins:
            total_in_value += tx_in.value(testnet=self.testnet)
            
        total_out_value = 0
        for tx_out in self.tx_outs:
            total_out_value += tx_out.amount
            
        return total_in_value - total_out_value
    
    # make sig_hash (SIGHASH_ALL ONLY)
    def sig_hash(self, input_index, redeem_script=None):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for idx, tx_in in enumerate(self.tx_ins):
            if idx == input_index:
                if redeem_script:
                    tx_in.script_sig = redeem_script
                else:
                    tx_in.script_sig = tx_in.get_script_lock(self.testnet)
            else:
                tx_in.script_sig = None
            result += TxInput(tx_in.prev_tx, tx_in.prev_index, tx_in.script_sig, tx_in.sequence).serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in enumerate(self.tx_outs):
            result += tx_out.serialize()
        result += int_to_little_endial(self.locktime, 4)
        result += int_to_little_endial(SIGHASH_ALL, 4)
        h256 = hash256(result)
        return int.from_bytes(h256, 'big')
    
    def verify_input(self, input_index):
        tx_in = self.tx_ins[input_index]
        script_lock = tx_in.get_script_lock(testnet=self.testnet)
        if script_lock.is_p2sh_script_pubkey():
            cmd = tx_in.script_sig.cmds[-1] # last element in script_sig of p2sh is redeem script
            redeem_for_parsing = encode_varint(len(cmd)) + cmd # for parsing
            redeem_script = script.parse(BytesIO(redeem_for_parsing))
        else:
            redeem_script = None
        z = self.sig_hash(input_index, redeem_script)
        combined_script = tx_in.script_sig + script_lock
        return combined_script.evalutate(z)
        
    def sign_input(self, input_index, private_key):
        # added for signing p2sh script
        tx_in = self.tx_ins[input_index]
        script_lock = tx_in.get_script_lock(testnet=self.testnet)
        if script_lock.is_p2sh_script_pubkey():
            cmd = tx_in.script_sig.cmds[-1] # last element in script_sig of p2sh is redeem script
            redeem_for_parsing = encode_varint(len(cmd)) + cmd # for parsing
            redeem_script = script.parse(BytesIO(redeem_for_parsing))
        else:
            redeem_script = None
        z = self.sig_hash(input_index, redeem_script)
        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = private_key.pubPoint.sec()
        script_sig = Script([sig, sec])
        self.tx_ins[input_index].script_sig = script_sig
        return self.verify_input(input_index)
    
    def verify_Tx(self):
        '''
        Verify the Tx
        1. fee >= 0
        2. valid UTXO input
        3. valid Signature
        '''
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True
    
        
# Transaction input class        
class TxInput:
    
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence
        
    def __repr__(self):
        return f'{self.prev_tx.hex()}:{self.prev_index}'
        
    @classmethod
    def parse(cls, s):
#         prev_tx = little_endian_to_int(s.read(32)) # need to check
        prev_tx = s.read(32)[::-1] # in bytes?
        prev_index = little_endian_to_int(s.read(4))
#         len_script_sig = read_varint(s)
#         script_sig = little_endian_to_int(s.read(len_script_sig))
        script_sig = script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)
    
    def serialize(self):
        '''Returns the byte of serialization of Tx input'''
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result
    
    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet)
    
    def value(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount
    
    def get_script_lock(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_lock
    
    
# Transacrion output class
class TxOutput:
    
    def __init__(self, amount, script_lock):
        self.amount = amount
        self.script_lock = script_lock
        
    def __repr__(self):
        return f'{self.amount}(in satosi):{self.script_lock}'
    
    @classmethod
    def parse(cls, s):
        amount = little_endian_to_int(s.read(8))
        script_lock = script.parse(s)
        return cls(amount, script_lock)
    
    def serialize(self):
        '''Returns the byte serialization of the Tx output'''
        result = int_to_little_endian(self.amount, 8)
        result += self.script_lock.serialize() # script class?
        return result
    
# Tx Fetcher class
class TxFetcher:
    
    cache = {}
    
    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'
        
    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache): # need to fetch
            url = f'{cls.get_url(testnet)}/tx/{tx_id}.hex'
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(f'unexpected response :{response.text}')
            if raw[4] == 0: # raw[4] == 0 은 어떤 케이스?
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError(f'not the same id: {tx.id()} vs {tx_id}')
                
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]





