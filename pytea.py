'''
# PyTEA module

    Simple implementation of TEA (Tiny Encryption Algorithm) Encryption 

    With 3 Block Cipher types:

        ECB         :       Electronic Code Book
        CBC         :       Cipher Block Chaining
        QQCBC       :       A Variation of CBC used by Tecent

    To use this module:

        import pytea
        >>> cipher = pytea.cbc_encrypt(b'some arbitrary text here',b'16characters')
        >>> pytea.cbc_decrypt(cipher,b'16characters')
        b'some arbitrary text here'
'''
import struct,ctypes,io,random
# region Primitive Types
class uint_32:
    '''
    Type for ctype `unit32_t`
    
    To access the value:
        `uint_32.value = 0`
    '''
    @staticmethod
    def c_uint32(v):
        '''Quantizes the value by utilizing ctypes'''
        return ctypes.c_uint32(v).value 

    def __init__(self,value):
        self._value = self.c_uint32(value)
        super().__init__()

    @property
    def value(self):
        '''Returns the value'''
        return self._value
    
    @value.setter
    def value(self,value):
        self._value = self.c_uint32(value)
# endregion

# region TEA
'''
A rather straightforward TEA Implementation

    From Wikipedia[https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm]:

        TEA operates on two 32-bit unsigned integers (could be derived from a 64-bit data block) and uses a 128-bit key. 

        It has a Feistel structure with a suggested 64 rounds, typically implemented in pairs termed cycles.
'''
def tea_block_encipher(v0,v1,k0,k1,k2,k3,n=32):
    '''Enciphers 2 Uint32 (4 Bytes) values
    
        Returns 2 enciphered unit32 values
    '''    
    delta = 0x9E3779B9
    # The magic constant, 2654435769 or 0x9E3779B9 is chosen to be ⌊2^32/ϕ⌋, where ϕ is the golden ratio (as a Nothing-up-my-sleeve number)
    v0,v1,k0,k1,k2,k3,_sum = [uint_32(v) for v in [v0,v1,k0,k1,k2,k3,0]]
    # setup,sum starts from 0
    for i in range(0,n):
        _sum.value = (_sum.value + delta)

        v0.value += ((v1.value<<4) + k0.value) ^ (v1.value + _sum.value) ^ ((v1.value>>5) + k1.value)
        v1.value += ((v0.value<<4) + k2.value) ^ (v0.value + _sum.value) ^ ((v0.value>>5) + k3.value)

    return v0.value,v1.value

def tea_block_decipher(v0,v1,k0,k1,k2,k3,n=32):
    '''Deciphers 2 Uint32 (4 Bytes) values
    
        Returns 2 deciphered unit32 values
    '''
    delta = 0x9E3779B9
    v0,v1,k0,k1,k2,k3,_sum = [uint_32(v) for v in [v0,v1,k0,k1,k2,k3,n * delta]]
    # setup,sum starts from n * delta
    for i in range(0,n):
        v1.value -= ((v0.value<<4) + k2.value) ^ (v0.value + _sum.value) ^ ((v0.value>>5) + k3.value)
        v0.value -= ((v1.value<<4) + k0.value) ^ (v1.value + _sum.value) ^ ((v1.value>>5) + k1.value)
        _sum.value = (_sum.value - delta) & 0xFFFFFFFF

    return v0.value,v1.value
# endregion

# region Padding
'''
Paddings to make byte length the multiple of n
'''
def no_padding(v:bytearray,**kw):
    '''No padding'''
    return v

def pad_simple(v:bytearray,l=8) -> bytearray:
    '''Simple padding without including padding length nor supports random padding chars'''
    return v + b'0' * (-len(v) % l)

def pad(v:bytearray,padding=lambda : random.randint(0,255),l=8) -> bytearray:
    '''
        Pads a bytearray to make its length to be a multiple of `l` with the padding length included
        
        Similar to what Tencent uses,this padding will pad with random characters
    '''
    fill_len = (-(len(v) + 2) % l) + 2
    # Makes sure the padding length is in range of 2 - 9 so that padding will always be applied,then put the value 
    # into the first byte by offsetting -2 to make it 0-7 (0b000~0b111 in binary) ,
    # fill the whole byte array with 7 `0` afterwards to make up 8 bytes
    # thus,the 1st byte will be the padding length,following the padding it self
    # then it's the data.Finally,we have 7 pad bytes
    return bytearray([0xF8 | (fill_len - 2)]) + bytearray([padding()]) * fill_len + v + b'0' * 7

def unpad(v:bytearray) -> bytearray:
    '''Unpads a padded value by `pad()`'''
    pad_length = (v[0] & 7) + 2
    # gets the padding length (by masking the 1st byte with 0b111)
    v = v[pad_length + 1:len(v) - 7]
    # stripes the array,only getting the real data (from the pad length byte to the last 7 pad bytes)
    return v

# endregion

# region Block cipher modes
'''
Block Cipher Modes for encryptions!

    referenced:

        ECB / CBC   :   https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
        QQCBC       :   https://www.geek-share.com/detail/2704250097.html
'''
def block(v:bytearray,blocksize=8) -> bytearray:
    '''Generator that generates `bytearray` at size of `blocksize` by padding with `padding`'''
    v = io.BytesIO(v)
    block = v.read(blocksize)
    while block:
        yield block
        block = v.read(blocksize)

# region Electronic Codebook (ECB)
def ecb_encrypt(v:bytearray,k:bytearray) -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA encryption'''
    ciphers,k,v = b'',struct.unpack('<IIII',pad_simple(k[:16],l=16)),pad(v)

    for plaintext in block(v):
        # Plaintext
        v0,v1 = struct.unpack('<II',plaintext)
        v0,v1 = tea_block_encipher(v0,v1,*k)
        # Block Cipher Encryption
        ciphers += struct.pack('<II',v0,v1)
        # Ciphertext
    return ciphers

def ecb_decrypt(v:bytearray,k:bytearray) -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA decryption'''
    plaintexts,k = b'',struct.unpack('<IIII',pad_simple(k[:16],l=16))
    for cipher in block(v):
        # Ciphertext
        v0,v1 = struct.unpack('<II',cipher)
        v0,v1 = tea_block_decipher(v0,v1,*k)
        # Block Cipher Decryption
        plaintexts += struct.pack('<II',v0,v1)
        # Plaintext
    return unpad(plaintexts)
# endregion

# region Cipher Block Chaining (CBC)
def xor(v1,v2):
    '''XOR eXclusive OR per byte'''
    v1,v2 = v1,pad_simple(v2[:len(v1)],l=len(v1))
    v = [v1[i] ^ v2[i] for i in range(0,len(v1))]
    return bytearray(v)

def cbc_encrypt(v:bytearray,k:bytearray,iv=b'0') -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA encryption'''
    ciphers,k,v = b'',struct.unpack('<IIII',pad_simple(k[:16],l=16)),pad(v)
    cipher0 = iv
    # First block should be initalized with Initialization Vector
    for plaintext in block(v):
        plaintext = xor(plaintext,cipher0)
        # Plaintext
        v0,v1 = struct.unpack('<II',plaintext)
        v0,v1 = tea_block_encipher(v0,v1,*k)
        cipher = struct.pack('<II',v0,v1)
        # Block Cipher Encryption
        cipher0 = cipher
        # Ciphertext
        ciphers += cipher
    return ciphers

def cbc_decrypt(v:bytearray,k:bytearray,iv=b'0') -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA decryption'''
    plaintexts,k = b'',struct.unpack('<IIII',pad_simple(k[:16],l=16))
    plaintext0 = iv
    for cipher in block(v):  
        # Cipher text
        v0,v1 = struct.unpack('<II',cipher)
        v0,v1 = tea_block_decipher(v0,v1,*k)
        plaintext = struct.pack('<II',v0,v1)
        # Block Cipher Decryption
        plaintext = xor(plaintext,plaintext0)
        plaintext0 = cipher
        # Plaintext
        plaintexts += plaintext 
    return unpad(plaintexts)
# endregion

# region QQ Cipher Block Chaining,Tencent's CBC (qqCBC)

def qqcbc_encrypt(v:bytearray,k:bytearray,iv=b'0') -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA encryption'''
    ciphers,k,v = b'',struct.unpack('<IIII',pad_simple(k[:16],l=16)),pad(v)
    cipher0 = iv
    # First block should be initalized with Initialization Vector
    for plaintext in block(v):
        plaintext = xor(plaintext,cipher0)
        # Plaintext
        v0,v1 = struct.unpack('<II',plaintext)
        v0,v1 = tea_block_encipher(v0,v1,*k)
        cipher = struct.pack('<II',v0,v1)
        # Block Cipher Encryption
        cipher0 = xor(cipher,xor(plaintext,cipher0))
        # Ciphertext
        ciphers += cipher
    return ciphers

def qqcbc_decrypt(v:bytearray,k:bytearray,iv=b'0') -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA decryption'''
    plaintexts,k = b'',struct.unpack('<IIII',pad_simple(k[:16],l=16))
    cipher0 = iv
    for cipher in block(v):  
        # Cipher text
        v0,v1 = struct.unpack('<II',cipher)
        v0,v1 = tea_block_decipher(v0,v1,*k)
        plaintext = struct.pack('<II',v0,v1)
        # Block Cipher Decryption
        plaintext = xor(plaintext,cipher0)
        cipher0 = xor(plaintext,cipher)
        # Plaintext
        plaintexts += plaintext 
    return unpad(plaintexts)
# endregion

# endregion

plaintext = b'am i right'
key = b'nononono'

print('Plain Text     ',plaintext)

enc = qqcbc_encrypt(plaintext,key)

print('Cipher Text     ',enc)

dec = qqcbc_decrypt(enc,key)

print('Deciphered Text ',dec)