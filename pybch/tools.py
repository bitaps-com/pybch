import hashlib
import binascii
import time
import random
import struct 
import hmac
from binascii import hexlify, unhexlify
from secp256k1 import lib as secp256k1
from secp256k1 import ffi


SIGHASH_FORKID = 0x40
SIGHASH_ALL           = 0x00000001
SIGHASH_NONE          = 0x00000002
SIGHASH_SINGLE        = 0x00000003
SIGHASH_ANYONECANPAY  = 0x00000080
MAX_INT_PRIVATE_KEY   = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
ECDSA_SEC256K1_ORDER  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HDW_PURPOSE           = 0x8000002C # bip 43
HDW_BITCOIN           = 0x80000000 # bitcoin

PREFIX_TESTNET = "bchtest"
PREFIX_MAINNET = "bitcoincash"
STRIPPED_PREFIX_MAINNET = b'\x02\t\x14\x03\x0f\t\x0e\x03\x01\x13\x08\x00'
STRIPPED_PREFIX_TESTNET = b'\x02\x03\x08\x14\x05\x13\x14\x00'

EC_COMPRESSED = secp256k1.SECP256K1_EC_COMPRESSED
EC_UNCOMPRESSED = secp256k1.SECP256K1_EC_UNCOMPRESSED

FLAG_SIGN = secp256k1.SECP256K1_CONTEXT_SIGN
FLAG_VERIFY = secp256k1.SECP256K1_CONTEXT_VERIFY
ALL_FLAGS = FLAG_SIGN | FLAG_VERIFY
NO_FLAGS = secp256k1.SECP256K1_CONTEXT_NONE

HAS_RECOVERABLE = hasattr(secp256k1, 'secp256k1_ecdsa_sign_recoverable')
HAS_SCHNORR = hasattr(secp256k1, 'secp256k1_schnorr_sign')
HAS_ECDH = hasattr(secp256k1, 'secp256k1_ecdh')

ECDSA_CONTEXT_SIGN = secp256k1.secp256k1_context_create(FLAG_SIGN)
ECDSA_CONTEXT_VERIFY = secp256k1.secp256k1_context_create(FLAG_VERIFY)
ECDSA_CONTEXT_ALL = secp256k1.secp256k1_context_create(ALL_FLAGS)
secp256k1.secp256k1_context_randomize(ECDSA_CONTEXT_SIGN,
                                      random.SystemRandom().randint(0,MAX_INT_PRIVATE_KEY).to_bytes(32,byteorder="big"))

SCRIPT_TYPES = { "P2PKH":        0,
                 "P2SH" :        1,
                 "PUBKEY":       2,
                 "NULL_DATA":    3,
                 "MULTISIG":     4,
                 "NON_STANDART": 5,
                 "SP2PKH": 6
                }

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

base32charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
base32charset_upcase = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"

int_base32_map = dict()
base32_int_map = dict()

for n, i in enumerate(base32charset):
    int_base32_map[i] = n
    base32_int_map[n] = ord(i)
for n, i in enumerate(base32charset_upcase):
    int_base32_map[i] = n

hash_size_map= {0: 160,
                1: 192,
                2: 224,
                3: 256,
                4: 320,
                5: 384,
                6: 448,
                7: 512}

#
# Encoding functions
#
def rebasebits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = bytearray()
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise Exception("invalid bytes")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise Exception("invalid padding")
    return ret

def rebase_5_to_8(data, pad = True):
    return rebasebits(data, 5, 8, pad)

def rebase_8_to_5(data, pad = True):
    return rebasebits(data, 8, 5, pad)

def rebase_32_to_5(data):
    if type(data) == bytes:
        data = data.decode()
    b = bytearray()
    try:
        for i in data:
            b.append(int_base32_map[i])
    except:
        raise Exception("Non base32 characters")
    return b

def rebase_5_to_32(data, bytes = True):
    r = bytearray()
    for i in data:
        r.append(base32_int_map[i])
    return r.decode() if not bytes else r

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        if c0 & 0x01 != 0:
            c ^= 0x98f2bc8e61
        if c0 & 0x02 != 0:
            c ^= 0x79b76d99e2
        if c0 & 0x04 != 0:
            c ^= 0xf33e5fb3c4
        if c0 & 0x08 != 0:
            c ^= 0xae2eabe2a8
        if c0 & 0x10 != 0:
            c ^= 0x1e4f43e470
    return c ^ 1

def encode_base58(b):
    """Encode bytes to a base58-encoded string"""
    # Convert big-endian bytes to integer
    n = int('0x0' + hexlify(b).decode('utf8'), 16)
    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])
    # Encode leading zeros as base58 zeros
    czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def decode_base58(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''
    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise Exception('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit
    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))
    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res

#
# Hash functions
#
def sha256(bytes):
    return hashlib.sha256(bytes).digest()

def double_sha256(bytes):
    return sha256(sha256(bytes))

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

def ripemd160(bytes):
    h = hashlib.new('ripemd160')
    h.update(bytes)
    return h.digest()

def hash160(bytes):
    return ripemd160(sha256(bytes))


#
# Bitcoin cash keys
#
def create_priv():
    """
    :return: 32 bytes private key 
    """
    q = time.time()
    rnd = random.SystemRandom()
    a = rnd.randint(0, MAX_INT_PRIVATE_KEY)
    i = int((time.time() % 0.01) * 100000)
    h = a.to_bytes(32, byteorder = "big")
    while True:
        h = hashlib.sha256(h).digest()
        if i > 1: i -= 1
        else:
            if int.from_bytes(h, byteorder = "big") < MAX_INT_PRIVATE_KEY:
                break
    return h

def priv_from_int(k):
    return int.to_bytes(k, byteorder = "big", length=32)


def priv2WIF(h, compressed = False, testnet = False):
    #uncompressed: 0x80 + [32-byte secret] + [4 bytes of Hash() of previous 33 bytes], base58 encoded
    #compressed: 0x80 + [32-byte secret] + 0x01 + [4 bytes of Hash() previous 34 bytes], base58 encoded
    prefix = b'\x80'
    if testnet:
        prefix = b'\xef'
    h = prefix + h
    if compressed: h += b'\x01' 
    h += hashlib.sha256(hashlib.sha256(h).digest()).digest()[:4]
    return encode_base58(h)

def WIF2priv(h):
    h = decode_base58(h)
    return h[1:33]

def is_WIF_valid(wif):
    if wif[0] not in ['5', 'K', 'L', '9', 'c']:
        return False
    h = decode_base58(wif)
    if len(h) != 37:  return False
    checksum = h[-4:]
    if hashlib.sha256(hashlib.sha256(h[:-4]).digest()).digest()[:4] != checksum: return False
    return True


def priv2pub(private_key, compressed = True, hex = False):
    if type(private_key)!= bytes:
        if type(private_key) == bytearray:
            private_key = bytes(private_key)
        elif type(private_key) == str:
            private_key = unhexlify(private_key)
        else:
            raise TypeError("private key must be a bytes or hex encoded string")
    pubkey_ptr = ffi.new('secp256k1_pubkey *')
    r = secp256k1.secp256k1_ec_pubkey_create(ECDSA_CONTEXT_ALL, pubkey_ptr, private_key)
    assert r == 1
    len_key = 33 if compressed else 65
    pubkey = ffi.new('char [%d]' % len_key)
    outlen = ffi.new('size_t *', len_key)
    compflag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED
    r = secp256k1.secp256k1_ec_pubkey_serialize(ECDSA_CONTEXT_VERIFY, pubkey, outlen, pubkey_ptr, compflag)
    assert r == 1
    pub = bytes(ffi.buffer(pubkey, len_key))
    return hexlify(pub).decode() if hex else pub


def is_valid_pub(key):
    if len(key) < 33:
        return False

    if key[0] == 0x04 and len(key) != 65:
        return False
    elif key[0] == 0x02 or key[0] == 0x03:
        if len(key) != 33:
            return False
    # else:  return  False
    return True

#
# Bitcoin cash addresses
#

def hash1602address(hash160, testnet = False, p2sh = False, legacy = False):
    if type(hash160) == str:
        hash160 = unhexlify(hash160)
    if legacy:
        if not p2sh:
            prefix = b'\x6f' if testnet else b'\x00'
        else:
            prefix = b'\xc4' if testnet else b'\x05'
        hash160 = prefix + hash160
        hash160 += double_sha256(hash160)[:4]
        return encode_base58(hash160)
    else:
        prefix = PREFIX_TESTNET if testnet else PREFIX_MAINNET
        stripped_prefix = STRIPPED_PREFIX_TESTNET if testnet else STRIPPED_PREFIX_MAINNET
        version = b"\x08" if p2sh else b"\x00"
        hash160 = rebase_8_to_5(version + hash160)
        checksum = bech32_polymod(stripped_prefix + hash160+b"\x00" * 8).to_bytes(5,"big")
        checksum = rebase_8_to_5(checksum)
        return "%s:%s" % (prefix, rebase_5_to_32(hash160 + checksum))


def address2hash160(address, hex = False):
    if address[0] in ('1','3', '2' 'm', 'n'):
        h = decode_base58(address)[1:-4]
    elif address.find(":") != -1 :
        address = address.split(":")[1]
        h =  rebase_5_to_8(rebase_32_to_5(address)[:-8], False)[1:]
    else:
        return None
    if hex:
        return hexlify(h).decode()
    else:
        return h


def address_type(address):
    if address[0] in ('2', '3', 'p'):
        return 'P2SH'
    elif address[0] in ('1', 'm', 'n'):
        return 'P2PKH'
    elif address.find(":") != -1 :
        if address.split(":")[1][0] == 'q':
            return 'P2PKH'
        elif address.split(":")[1][0] == 'p':
            return 'P2SH'
    return 'UNKNOWN'


def pub2address(pubkey, testnet = False, legacy = False, p2sh = False):
    h = hash160(pubkey)
    return address2hash160(h, testnet = testnet, legacy = legacy, p2sh = p2sh)


def is_address_valid(addr, testnet = False):
    if addr.find(":") == -1:
        if testnet:
            if addr[0] not in ('m', 'n', '2'):
                return False
        else:
            if addr[0] not in ('1','3'):
                return False
        h = decode_base58(addr)
        if len(h) != 25:  return False
        checksum = h[-4:]
        if hashlib.sha256(hashlib.sha256(h[:-4]).digest()).digest()[:4] != checksum: return False
        return True
    else:
        prefix, payload = addr.split(':')
        upp = True if payload[0].isupper() else False
        for i in payload[1:]:
            if upp and not i.isupper():
                return False
            elif i.isupper():
                return False


        stripped_prefix = STRIPPED_PREFIX_TESTNET if testnet else STRIPPED_PREFIX_MAINNET
        if testnet:
            if prefix != PREFIX_TESTNET:
                return False
        else:
            if prefix != PREFIX_MAINNET:
                return False
        d = rebase_32_to_5(payload)
        f = ((len(d) * 5) - 48) - hash_size_map[d[1] & 0b11100000]
        if  f > 5 or f < 0:
            return False
        elif d[-9] & (0b11111 >> (5-f)):
            # non zero padding
            return False
        ch = bech32_polymod(stripped_prefix + d[:-8] + b"\x00" * 8).to_bytes(5, "big")
        if rebase_8_to_5(ch) != d[-8:]:
            return False
        return True


#
# ECDSA
#

def verify_signature(sig, pubKey, msg):
    if type(sig) != bytes:
        if type(sig) == bytearray:
            sig = bytes(sig)

        elif type(sig) == str:
            sig = unhexlify(sig)
        else :
            raise TypeError("signature must be a bytes or hex encoded string")
    if type(pubKey) != bytes:
        if type(pubKey) == bytearray:
            pubKey = bytes(pubKey)

        elif type(pubKey) == str:
            pubKey = unhexlify(pubKey)
        else :
            raise TypeError("public key must be a bytes or hex encoded string")

    if type(msg) != bytes:
        if type(msg) == bytearray:
            msg = bytes(msg)
        elif type(msg) == str:
            msg = unhexlify(msg)
        else:
            raise TypeError("message must be a bytes or hex encoded string")

    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    raw_pubkey = ffi.new('secp256k1_pubkey *')
    if not secp256k1.secp256k1_ecdsa_signature_parse_der(ECDSA_CONTEXT_VERIFY , raw_sig, sig, len(sig)):
        raise TypeError("signature must be DER encoded")
    if not secp256k1.secp256k1_ec_pubkey_parse(ECDSA_CONTEXT_VERIFY, raw_pubkey, pubKey, len(pubKey)):
        raise TypeError("public key format error")
    result = secp256k1.secp256k1_ecdsa_verify(ECDSA_CONTEXT_VERIFY, raw_sig, msg, raw_pubkey)
    return True if result else False

def sign_message(msg, private_key, hex = False):
    """
    :param msg:  message to sign 
    :param private_key:  private key (bytes, hex encoded string)
    :param hex:  
    :return:  DER encoded sinature  
    """
    if type(msg) != bytes:
        if type(msg) == bytearray:
            msg = bytes(msg)

        elif type(msg) == str:
            msg = unhexlify(msg)
        else :
            raise TypeError("message must be a bytes or hex encoded string")
    if type(private_key)!= bytes:
        if type(private_key) == bytearray:
            private_key = bytes(private_key)
        elif type(private_key) == str:
            private_key = unhexlify(private_key)
        else:
            raise TypeError("private key must be a bytes or hex encoded string")
    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    signed = secp256k1.secp256k1_ecdsa_sign(ECDSA_CONTEXT_SIGN, raw_sig, msg, private_key, ffi.NULL, ffi.NULL)
    assert signed == 1
    len_sig = 74
    output = ffi.new('unsigned char[%d]' % len_sig)
    outputlen = ffi.new('size_t *', len_sig)
    res = secp256k1.secp256k1_ecdsa_signature_serialize_der(ECDSA_CONTEXT_SIGN, output, outputlen, raw_sig)
    assert res == 1
    signature =  bytes(ffi.buffer(output, outputlen[0]))
    return hexlify(signature).decode() if hex else signature

def is_valid_signature_encoding(sig):
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    # * total-length: 1-byte length descriptor of everything that follows,
    #   excluding the sighash byte.
    # * R-length: 1-byte length descriptor of the R value that follows.
    # * R: arbitrary-length big-endian encoded R value. It must use the shortest
    #   possible encoding for a positive integers (which means no null bytes at
    #   the start, except a single one when the next byte has its highest bit set).
    # * S-length: 1-byte length descriptor of the S value that follows.
    # * S: arbitrary-length big-endian encoded S value. The same rules apply.
    # * sighash: 1-byte value indicating what data is hashed (not part of the DER
    #   signature)

    length = len(sig)
    # Minimum and maximum size constraints.
    if (length < 9) or (length > 73):
        return False
    # A signature is of type 0x30 (compound).
    if sig[0] != 0x30:
        return False
    # Make sure the length covers the entire signature.
    if sig[1] != (length - 3):
        return False
    # Extract the length of the R element.
    lenR = sig[3]
    # Make sure the length of the S element is still inside the signature.
    if (5 + lenR) >= length:
        return False
    # Extract the length of the S element.
    lenS = sig[5 + lenR]
    # Verify that the length of the signature matches the sum of the length
    # of the elements.
    if (lenR + lenS + 7) != length:
        return False
    # Check whether the R element is an integer.
    if sig[2] != 0x02:
        return False
    # Zero-length integers are not allowed for R.
    if lenR == 0:
        return False
    # Negative numbers are not allowed for R.
    if sig[4] & 0x80:
        return False
    # Null bytes at the start of R are not allowed, unless R would
    # otherwise be interpreted as a negative number.
    if (lenR > 1) and (sig[4] == 0x00) and (not sig[5] & 0x80):
        return False
    # Check whether the S element is an integer.
    if sig[lenR + 4] != 0x02:
        return False
    # Zero-length integers are not allowed for S.
    if lenS == 0:
        return False
    # Negative numbers are not allowed for S.
    if sig[lenR + 6] & 0x80:
        return False
    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if (lenS > 1) and (sig[lenR + 6] == 0x00) and (not sig[lenR + 7] & 0x80):
        return False
    return True


#
# Transaction encoding
#

def rh2s(tthash):
    return hexlify(tthash[::-1]).decode()

def s2rh(hash_string):
    return unhexlify(hash_string)[::-1]

def merkleroot(tx_hash_list):
    tx_hash_list = list(tx_hash_list)
    if len(tx_hash_list) == 1:
        return tx_hash_list[0]
    while True:
        new_hash_list = list()
        while tx_hash_list:
            h1 = tx_hash_list.pop()
            try:
                h2 = tx_hash_list.pop()
            except:
                h2 = h1
            new_hash_list.insert(0, double_sha256(h1 + h2))
        if len(new_hash_list) > 1:
            tx_hash_list = new_hash_list
        else:
            return new_hash_list[0]





#
#
#


def var_int(data):
    e, s = 1, 0
    if data[:1] == b'\xfd':
        s, e = 1, 3
    elif data[:1] == b'\xfe':
        s = 1
        e = 5
    elif data[:1] == b'\xff':
        s = 1
        e = 9
    i = int.from_bytes(data[s:e], byteorder='little', signed=False)
    return (i, e)


def from_var_int(data):
    # retrun
    e = 1
    s = 0
    if data[:1] == b'\xfd':
        s = 1
        e = 3
    elif data[:1] == b'\xfe':
        s = 1
        e = 5
    elif data[:1] == b'\xff':
        s = 1
        e = 9
    i = int.from_bytes(data[s:e], byteorder='little', signed=False)
    return i


def var_int_len(byte):
    e = 1
    if byte == 253:
        e = 3
    elif byte == 254:
        e = 5
    elif byte == 255:
        e = 9
    return e


def to_var_int(i):
    if i < 253:
        return i.to_bytes(1, byteorder='little')
    if i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, byteorder='little')
    if i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, byteorder='little')
    return b'\xff' + i.to_bytes(8, byteorder='little')


def read_var_int(stream):
    l = stream.read(1)
    bytes_length = var_int_len(l[0])
    return l + stream.read(bytes_length - 1)


def read_var_list(stream, data_type):
    count = from_var_int(read_var_int(stream))
    return [data_type.deserialize(stream) for i in range(count)]


def merkleroot(tx_hash_list):
    tx_hash_list = list(tx_hash_list)
    if len(tx_hash_list) == 1:
        return tx_hash_list[0]
    while True:
        new_hash_list = list()
        while tx_hash_list:
            h1 = tx_hash_list.pop()
            try:
                h2 = tx_hash_list.pop()
            except:
                h2 = h1
            new_hash_list.insert(0, double_sha256(h1 + h2))
        if len(new_hash_list) > 1:
            tx_hash_list = new_hash_list
        else:
            return new_hash_list[0]

# generic big endian MPI format
def bn_bytes(v, have_ext=False):
    ext = 0
    if have_ext:
        ext = 1
    return ((v.bit_length() + 7) // 8) + ext


def bn2bin(v):
    s = bytearray()
    i = bn_bytes(v)
    while i > 0:
        s.append((v >> ((i - 1) * 8)) & 0xff)
        i -= 1
    return s


def bin2bn(s):
    l = 0
    for ch in s:
        l = (l << 8) | ch
    return l


def bn2mpi(v):
    have_ext = False
    if v.bit_length() > 0:
        have_ext = (v.bit_length() & 0x07) == 0

    neg = False
    if v < 0:
        neg = True
        v = -v

    s = struct.pack(b">I", bn_bytes(v, have_ext))
    ext = bytearray()
    if have_ext:
        ext.append(0)
    v_bin = bn2bin(v)
    if neg:
        if have_ext:
            ext[0] |= 0x80
        else:
            v_bin[0] |= 0x80
    return s + ext + v_bin


def mpi2bn(s):
    if len(s) < 4:
        return None
    s_size = bytes(s[:4])
    v_len = struct.unpack(b">I", s_size)[0]
    if len(s) != (v_len + 4):
        return None
    if v_len == 0:
        return 0

    v_str = bytearray(s[4:])
    neg = False
    i = v_str[0]
    if i & 0x80:
        neg = True
        i &= ~0x80
        v_str[0] = i

    v = bin2bn(v_str)

    if neg:
        return -v
    return v

# bitcoin-specific little endian format, with implicit size


def mpi2vch(s):
    r = s[4:]           # strip size
    # if r:
    r = r[::-1]         # reverse string, converting BE->LE
    # else: r=b'\x00'
    return r


def bn2vch(v):
    return bytes(mpi2vch(bn2mpi(v)))


def vch2mpi(s):
    r = struct.pack(b">I", len(s))   # size
    r += s[::-1]            # reverse string, converting LE->BE
    return r


def vch2bn(s):
    return mpi2bn(vch2mpi(s))


def i2b(i): return bn2vch(i)


def b2i(b): return vch2bn(b)


   





