from io import BytesIO
from helper import (
    encode_varint,
    little_endian_to_int,
    int_to_little_endian,
    read_varint,
    encode_varint,)
from op import OP_CODE_FUNCTIONS, OP_CODE_NAMES

def get_p2pkh_script_lock(h160):
    # OP_DUP, OP_HASH160, hash160 value, OP_EQUALVERIFY, OPCHECKSIG 
    return script([0x76, 0xa9, h160, 0x88, 0xac])

class script:
    # do not include logger
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds
            
    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)
            
    def __add__(self, other):
        return self.__class__(self.cmds + other.cmds)
    
    def evaluate(self, z):
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop()
            # command (op_code)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                
                # categorize with respect to input for the operation
                
                # OP_IF, OP_NOTIF
                if cmd in (99, 100):
                    if not operation(stack, cmds):
                        return False
                
                # OP_TOALTSTACK, OPFROMALTSTACK
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        return False
                
                # OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
                elif cmd in range(172, 176):
                    if not operation(stack, z):
                        return False
                
                # else OP_CODE
                else:
                    if not operation(stack):
                        return False
            
            # element
            else:
                stack.append(cmd)
                # screening script hash type : OP_HASH160 + hash 160 value + OP_EQUAL
                if len(cmds) == 3 and cmds[0] == 0xa9 \
                    and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                    and cmds[2] == 0x87:
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):
                        return False
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(script.parse(stream).cmds)
        
        if len(stack) == 0: # should not be empty
            return False
        
        if stack.pop() == b'':  # 0 means fail
            return False
        
        return True
            
    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            # 1~78 : element, else: op_command
            current_byte = s.read(1)[0]
            count += 1
            # if element shorter than 76 byte,
            if current_byte >= 1 and current_byte <= 75:
                len_element = current_byte
                cmds.append(s.read(len_element))
                count += len_element
                
            # OP_PUSHDATA1 (76~255 bytes)
            elif current_byte == 76:
                len_element = little_endian_to_int(s.read(1))
                cmds.append(s.read(len_element))
                count += len_element + 1
            
            # OP_PUSHDATA2 (256~520 bytes)
            elif current_byte == 77:
                len_element = little_endian_to_int(s.read(2))
                cmds.append(s.read(len_element))
                count += len_element + 2
            
            # command
            else:
                op_code = current_byte
                cmds.append(op_code)
                
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)
    
    def raw_serialize(self):
        result = b''
        # cmd should be consist of command (int) and element (byte)
        for cmd in self.cmds:
            # op_command if its type is int
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            # if its type is byte, element
            else:
                len_element = len(cmd)
                
                # First, add length of element
                if len_element < 75:
                    result += int_to_little_endian(len_element, 1)
                elif len_element > 75 and len_element < 0x100:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(len_element, 1)
                elif len_element >= 0x100 and len_element <= 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(len_element, 2)
                else:
                    raise ValueError('too long cmd')
                # after length, add element
                result += cmd
        return result
    
    def serialize(self):
        raw_serialized = self.raw_serialize()
        len_script = len(raw_serialized)
        return encode_varint(len_script) + raw_serialized
    
    def is_p2pkh_script_lock(self):
        # OP_DUP + OP_HASH160 + hash160 + OP_EQUALVERIFY + OP_CHECKSIG
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 \
            and self.cmds[1] == 0xa9 \
            and type(self.comds[2]) == bytes and len(self.cmds[2]) == 20 \ 
            and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    def is_p2sh_script_lock(self):
        # OP_HASH160 + hash160 + OP_EQUAL
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 \
            and self.cmds[2] == 0x87
