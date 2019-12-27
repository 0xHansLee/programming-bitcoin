#!/usr/bin/env python
# coding: utf-8

# In[322]:


from random import randint
import hashlib
import hmac
from helper import encode_base58_checksum, hash160
from io import BytesIO

## Finite Field Element class

class FiniteFieldElement:
    
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime-1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime
        
    def __repr__(self):
        return f'FiniteFieldElement : {self.num}({self.prime})'
    
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime
    
    def __ne__(self, other):
        return not(self == other)
    
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        # return with the same class
        return self.__class__(num, self.prime)
    
    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __mul__(self,other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)
    
    # division (using Fermat's little theorem)
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        return self.__class__(num, self.prime)
    
    # right multiplication (scalar multiplication of Finite Field Element)
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num, self.prime)
    
    
## Point on Elliptic Curve class
# Elliptic Curve : y^2 = x^3 + a*x + b

class ECPoint:
    
    def __init__(self, x, y, a, b):
        self.x = x
        self.y = y
        self.a = a
        self.b = b
        if x is None and y is None:
            return
        if x is None or y is None:
            raise TypeError(f'({self.x}, {self.y}) is not on the curve')
        if (self.y ** 2) != ((self.x ** 3) + self.a * self.x + self.b):
            raise ValueError(f'({self.x}, {self.y}) is not on the curve')
        
    def __eq__(self, other):
        return (self.x, self.y, self.a, self.b) == (other.x, other.y, other.a, other.b) 
        
    def __ne__(self, other):
        return not(self == other)
        
    def __repr__(self):
        if self.x is None and self.y is None:
            return 'ECPoint(infinity)'
        elif isinstance(self.x, FiniteFieldElement):
            return f'ECPoint({self.x}, {self.y}) on ({self.a}, {self.b}) FinteFieldElement({self.x.prime})'
        else:
            return f'ECPoint({self.x}, {self.y}) on ({self.a}, {self.b})'
        
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'Points {self}, {other} are not on the same curve')
        
        # case 0.0 : self is the point at infinity, returh other
        if self.x is None:
            return other
        
        # case 0.1 : other is the point at infinity, return self
        if other.x is None:
            return self
        
        # case 1 : self.x == other.x, self.y != other.y
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        
        # case 2 : self.y == other.y == 0
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        
        # case 3 : self != other
        if self != other:
            s = (other.y - self.y) / (other.x - self.x)
            x = s ** 2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        
        # case 4 : self == other
        if self == other:
            s = (3 * self.x ** 2 + self.a) / (2 * self.y)
            x = s ** 2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        
    # right multiplication (for scalar multiplication of ECPoint)
    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result
        
## SECP256K1 Elliptic Curve for Bitcoin
# y^2 = x^3 + 7

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

## SECP256K1 Field Element
class S256Field(FiniteFieldElement):
    
    def __init__(self, num, prime=None):
        super().__init__(num, P)
        
    def __repr__(self):
        return f'{self.num:x}'.zfill(64)
    
    def sqrt(self):
        return self**((P + 1) // 4)

## Point class on SECP256K1 curve
class S256Point(ECPoint):
    
    def __init__(self, x, y, a=None, b=None):
        a = S256Field(A)
        b = S256Field(B)
        if type(x) == int:
            super().__init__(S256Field(x), S256Field(y), a, b)
        else:
            super().__init__(x, y, a, b)
            
    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return f'S256Point({self.x}, {self.y})'
        
    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)
    
    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        res = u * G + v * self
        return res.x.num == sig.r
    
    def sec(self, compressed=True):
        '''returns the binary version of the SEC format'''
        if compressed:
            # y is even : 0x02 + ~
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            # y is odd : 0x03 + ~
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
    
    @classmethod    
    def parse(cls, sec_bin):
        '''returns a S256Point Object from a SEC binary (not hex)'''
        
        # Uncompressed
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return cls(x, y)
        
        # compressed
        elif sec_bin[0] == 2 or sec_bin[0] == 3:
            x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
            y1 = (x**3 + S256Field(B)).sqrt()
            y2 = S256Field(P - y1.num)
            if sec_bin[0] == 2:
                return cls(x, y1 if y1.num % 2 == 0 else y2)
            else:
                return cls(x, y1 if y1.num % 2 == 1 else y2)
        else:
            raise ValueError('Wrong public key')
            
    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))
    
    def address(self, compressed=True, testnet=False):
        '''Returns the address string'''
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)
            
        
G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


## Signature class using S256Point
class Signature:
    
    def __init__(self, r, s):
        self.r = r
        self.s = s
    
    def __repr__(self):
        return f'Signature(r : {self.r}, s : {self.s})'
    
    def der(self):
        rbin = self.r.to_bytes(32, 'big')
        # remove null bytes (\x00)
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        
        # result : 0x02 + length(r) + r
        result = bytes([2, len(rbin)]) + rbin
        
        sbin = self.s.to_bytes(32, 'big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
            
        # result : 0x02 + length(r) + r + 0x02 + length(s) + s
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result
        
    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)
    
## PrivageKey class    
class PrivateKey:
    
    def __init__(self, privKey):
        self.privKey = privKey
        self.pubPoint = privKey * G
        
    def hex(self):
        return f'{privKey:x}'.zfill(64)
    
    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N-2, N)
        s = (z + r * self.privKey) * k_inv % N
        if s > N/2:
            s = N-s
        return Signature(r, s)
    
    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate  # <2>
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()
            
    def wif(self, compressed=True, testnet=False):
        priv_bytes = self.privKey.to_bytes(32, 'big')
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        return encode_base58_checksum(prefix + priv_bytes + suffix)

