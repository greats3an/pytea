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

# region TEA
'''
A rather straightforward TEA Implementation

    From Wikipedia[https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm]:

        TEA operates on two 32-bit unsigned integers (could be derived from a 64-bit data block) and uses a 128-bit key. 

        It has a Feistel structure with a suggested 64 rounds, typically implemented in pairs termed cycles.
'''
def bytecipher(cipherer):
    '''
    Takes 2 `bytearray`s,then unpacks them into `uint_32`s to the cipherers
    
    Once ciphered,the `uint_32`s will be pack into 2 `bytearray`s
    '''
    def wrapper(v:bytearray,k:bytearray,n=32):
        v,k = pad_simple(v,l=8),pad_simple(k,l=16)
        v = struct.unpack('<II',v)
        k = struct.unpack('<IIII',k)
        result = cipherer(*v,*k,n=n)
        result = struct.pack('<II',*result)
        return result
    return wrapper
@bytecipher
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
@bytecipher
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
    ciphers,v = b'',pad(v)
    for _block in block(v):
        # Plaintext
        cipher = tea_block_encipher(_block,k)
        # Block Cipher Encryption
        ciphers += cipher
        # Ciphertext
    return ciphers

def ecb_decrypt(v:bytearray,k:bytearray) -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA decryption'''
    plaintexts = b''
    for _block in block(v):
        # Ciphertext
        plaintext = tea_block_decipher(_block,k)
        # Block Cipher Decryption
        plaintexts += plaintext
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
    ciphers,v = b'',pad(v)
    cipher0 = iv
    # First block should be initalized with Initialization Vector
    for _block in block(v):
        plaintext = xor(_block,cipher0)
        # Plaintext
        cipher = tea_block_encipher(plaintext,k)
        # Block Cipher Encryption
        cipher0 = cipher
        # Ciphertext
        ciphers += cipher
    return ciphers

def cbc_decrypt(v:bytearray,k:bytearray,iv=b'0') -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA decryption'''
    plaintexts = b''
    plaintext0 = iv
    for _block in block(v):  
        # Cipher text
        plaintext = tea_block_decipher(_block,k)
        # Block Cipher Decryption
        plaintext = xor(plaintext,plaintext0)
        plaintext0 = _block
        # Plaintext
        plaintexts += plaintext 
    return unpad(plaintexts)
# endregion

# region QQ Cipher Block Chaining,Tencent's CBC (qqCBC)

def qqcbc_encrypt(v:bytearray,k:bytearray,iv0=b'0',iv1=b'0') -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA encryption'''
    ciphers,v = b'',pad(v)
    cipher0,plaintext0 = iv0,iv1
    # First block should be initalized with Initialization Vector
    for _block in block(v):
        plaintext = xor(_block,cipher0)
        # Plaintext
        cipher = tea_block_encipher(plaintext,k)
        # Block Cipher Encryption
        cipher = xor(cipher,plaintext0)

        cipher0 = cipher
        plaintext0 = plaintext
        
        # Ciphertext
        ciphers += cipher
    return ciphers

def qqcbc_decrypt(v:bytearray,k:bytearray,iv0=b'0',iv1=b'0') -> bytearray:
    '''Takes a byte array,for every `8` bytes of them,perform TEA decryption'''
    plaintexts = b''
    cipher0,plaintext0 = iv0,iv1
    for _block in block(v):  
        # Cipher text
        cipher = xor(_block,plaintext0)

        plaintext = tea_block_decipher(cipher,k)
        # Block Cipher Decryption          
        plaintext0 = plaintext
        plaintext = xor(plaintext,cipher0)
        cipher0 = _block

        # Plaintext
        plaintexts += plaintext 
    return unpad(plaintexts)
# endregion

# endregion
if __name__ == "__main__":
    plaintext = b'Some arbitary length text here'
    key = b'0102030405060708'

    print('ECB Test')
    print('Plain Text     ',plaintext)
    enc = ecb_encrypt(plaintext,key)
    print('Cipher Text     ',enc)
    dec = ecb_decrypt(enc,key)
    print('Deciphered Text ',dec)
    print()
    print('CBC Test')
    print('Plain Text     ',plaintext)
    enc = cbc_encrypt(plaintext,key)
    print('Cipher Text     ',enc)
    dec = cbc_decrypt(enc,key)
    print('Deciphered Text ',dec)
    print()
    print('QQCBC Test')
    print('Plain Text     ',plaintext)
    enc = qqcbc_encrypt(plaintext,key)
    print('Cipher Text     ',enc)
    dec = qqcbc_decrypt(enc,key)
    # CY\x0cB\xee\xdcLo\xe2\x8e\x83\x10d\xb4\x98u\x9f\x9e0\xaa?\xda\xfb\x9f
    print('Deciphered Text ',dec)