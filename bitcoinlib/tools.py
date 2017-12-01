import hashlib
import binascii
from   ctypes import *
import ipaddress
import struct
import asyncio
import time
import random
import struct 
import hmac

ECDSA = cdll.LoadLibrary("libsecp256k1.so")
SIGHASH_ALL           = 0x00000001
SIGHASH_NONE          = 0x00000002
SIGHASH_SINGLE        = 0x00000003
SIGHASH_ANYONECANPAY  = 0x00000080
MAX_INT_PRIVATE_KEY   = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
ECDSA_SEC256K1_ORDER  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HDW_PURPOSE           = 0x8000002C # bip 43
HDW_BITCOIN           = 0x80000000 # bitcoin

# /** All flags' lower 8 bits indicate what they're for. Do not use directly. */
SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
# /** The higher bits contain the actual data. Do not use directly. */
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

# /** Flags to pass to secp256k1_context_create. */
SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT)

SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)
SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)

SCRIPT_TYPES = { "P2PKH":        0,
                 "P2SH" :        1,
                 "PUBKEY":       2,
                 "NULL_DATA":    3,
                 "MULTISIG":     4,
                 "NON_STANDART": 5,
                 "SP2PKH": 6
                }
###### FIX
ECDSA_VERIFY_CONTEXT = ECDSA.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

inventory_type = {
    1: 'ERROR',
    2: 'MSG_TX',
    3: 'MSG_BLOCK',
    4: 'MSG_FILTERED_BLOCK',
    'ERROR': 0,
    'MSG_TX': 1,
    'MSG_BLOCK': 2,
    'MSG_FILTERED_BLOCK': 3
}


def encode_base58(b):
    """Encode bytes to a base58-encoded string"""
    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('utf8'), 16)
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
    res = binascii.unhexlify(h.encode('utf8'))
    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()


# Bitcoin keys 
#
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
    h=decode_base58(h)
    return h[1:33]

def is_WIF_valid(wif):
    if wif[0] not in ['5', 'K', 'L', '9', 'c']:
        return False
    h = decode_base58(wif)
    if len(h) != 37:  return False
    checksum = h[-4:]
    if hashlib.sha256(hashlib.sha256(h[:-4]).digest()).digest()[:4] != checksum: return False
    return True


def priv2pub(private_key, compressed = SECP256K1_EC_UNCOMPRESSED):
    pub = create_string_buffer(64)
    ECDSA.secp256k1_ec_pubkey_create(ECDSA_VERIFY_CONTEXT, pub, c_char_p(private_key))
    pp = create_string_buffer(65)
    s = c_int(65)
    ECDSA.secp256k1_ec_pubkey_serialize(ECDSA_VERIFY_CONTEXT, pp, pointer(s), pub, compressed)
    return pp.raw[:s.value]


def pub2address (pubkey, testnet = False):
    if not testnet:
        return v_ripemd2address(b'\x00' + pub2ripemd160(pubkey))
    else:
        return v_ripemd2address(b'\x6f' + pub2ripemd160(pubkey))



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


def pub2ripemd160(pubkey):
    return ripemd160(hashlib.sha256(pubkey).digest())

def v_ripemd2address(h):
    h += hashlib.sha256(hashlib.sha256(h).digest()).digest()[:4]
    return encode_base58(h)

def ripemd2address(h, testnet = False, p2sh = False):
    if not p2sh:
        prefix = b'\x6f' if testnet else b'\x00'
    else:
        prefix = b'\xc4' if testnet else b'\x05'
    h = prefix + h
    h += hashlib.sha256(hashlib.sha256(h).digest()).digest()[:4]
    return encode_base58(h)



# BIP32 
#
#
#

def BIP32_create_master():
    rnd = random.SystemRandom()
    a = rnd.randint(0,MAX_INT_PRIVATE_KEY)
    i = int((time.time()%0.01)*100000)
    h = a.to_bytes(32,byteorder="big")
    Key = b"Bitcoin seed"
    while True:
        h = hashlib.sha256(h).digest()
        if i>1: i -= 1
        else:
            if int.from_bytes(h,byteorder="big")<MAX_INT_PRIVATE_KEY:
                break
    I = hmac_sha512(Key,h) 
    M, C = I[:32], I[32:]
    return b'\x04\x88\xAD\xE4\x00\x00\x00\x00\x00\x00\x00\x00\x00'+C+b'\x00'+M

def CKDpriv(extended_master_key, i):
    C = extended_master_key[13:45]
    M = extended_master_key[45:]
    version = extended_master_key[:4]
    depth = int.from_bytes(extended_master_key[4:5],byteorder='big')+1
    if depth > 255: return None
    Mpub = priv2pub(M[1:], True)
    I = hmac_sha512(C,M+struct.pack(">L", i)) if i >= 0x80000000\
    else hmac_sha512(C, Mpub+struct.pack(">L", i))
    code = I[32:]
    Iln = int.from_bytes(I[:32],byteorder='big')
    if Iln > ECDSA_SEC256K1_ORDER: return None
    k_int = (int.from_bytes(M[1:],byteorder='big')+Iln)%ECDSA_SEC256K1_ORDER
    if k_int == 0:  return None
    key = priv_from_int(k_int)
    return version + depth.to_bytes(1, byteorder='big') + pub2ripemd160(Mpub)[:4] + i.to_bytes(4, byteorder='big') + code + b'\x00' + key

def CKDpub(extended_master_key, i):
    C = extended_master_key[13:45]
    Mpub = extended_master_key[45:]
    version = extended_master_key[:4]
    depth = int.from_bytes(extended_master_key[4:5],byteorder='big')+1
    if depth > 255 or i >= 0x80000000: return None
    I = hmac_sha512(C,Mpub+struct.pack(">L", i))
    code = I[32:]
    if int.from_bytes(I[:32],byteorder='big') > ECDSA_SEC256K1_ORDER: return None
    pk = create_string_buffer(64)
    if not ECDSA.secp256k1_ec_pubkey_parse(ECDSA_VERIFY_CONTEXT, pk, Mpub, len(Mpub)): return None
    if not ECDSA.secp256k1_ec_pubkey_tweak_add(ECDSA_VERIFY_CONTEXT, pk, I[:32]) : return None
    pp = create_string_buffer(65)
    s = c_int(65)
    ECDSA.secp256k1_ec_pubkey_serialize(ECDSA_VERIFY_CONTEXT,pp,pointer(s),pk,1)
    key = pp.raw[:s.value]
    return version + depth.to_bytes(1, byteorder='big') + pub2ripemd160(Mpub)[:4] + i.to_bytes(4, byteorder='big') + code + key

def ext_key_base58(k):
    k += double_sha256(k)[:4]
    return encode_base58(k)

def base58_to_ext_key(k):
    k = decode_base58(k)
    return k[:-4]

def BIP32_derive_key(extended_master_key, path, index):
    # m / purpose' / coin_type' / account' / change / address_index
    # 0x0488B21E public, 0x0488ADE4 private;
    # purpose = 0x8000002C
    # coin_tipe = 0x80000000
    version = extended_master_key[:4]
    depth = int.from_bytes(extended_master_key[4:5],byteorder='big')
    if depth > len(path): return None
    path = path[depth:]
    if version == b'\x04\x88\xAD\xE4':
        # derive private key
        for p in path: extended_master_key = CKDpriv(extended_master_key, p)
        return CKDpriv(extended_master_key, index)
    elif version == b'\x04\x88\xB2\x1E':
        # derive public key
        for p in path: extended_master_key = CKDpub(extended_master_key, p)
        return CKDpub(extended_master_key, index)

def xpub_from_xpriv(xpriv):
    Mpub = priv2pub(xpriv[46:], True)
    return b'\x04\x88\xB2\x1E'+xpriv[4:45]+Mpub




def get_tx_inventory(raw_tx):
    h = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
    h2 = binascii.hexlify(h[::-1])
    return (b'\x01\x00\x00\x00' + h, h2)


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

def ripemd160(byte_string):
    h = hashlib.new('ripemd160')
    h.update(byte_string)
    return h.digest()




def double_sha256(byte_string):
    return hashlib.sha256(hashlib.sha256(byte_string).digest()).digest()

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


def check_sig(sig, pubKey, sigHash, ECDSA_CONTEXT):
    sgn = create_string_buffer(65)
    pk = create_string_buffer(64)

    if not ECDSA.secp256k1_ecdsa_signature_parse_der(ECDSA_CONTEXT, sgn, sig, len(sig)):
        return 0
        raise Exception('signature parse error')

    if not ECDSA.secp256k1_ec_pubkey_parse(ECDSA_CONTEXT, pk, pubKey, len(pubKey)):
        return 0
        raise Exception('pubkey parse error')

    result = ECDSA.secp256k1_ecdsa_verify(ECDSA_CONTEXT, sigHash, sgn, pk)
    return result


def rh2s(tthash):
    return binascii.hexlify(tthash[::-1]).decode()

async def get_pipe_stream_reader(fd_reader, loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    try:
        transport, x = await loop.connect_read_pipe(lambda: protocol, fd_reader)
    except:
        return None
    return reader


async def pipe_get_msg(reader):
    while True:
        try:
            msg = await reader.readexactly(1)
            if msg == b'M':
                msg = await reader.readexactly(1)
                if msg == b'E':
                    msg = await reader.readexactly(4)
                    c = int.from_bytes(msg, byteorder='little')
                    msg = await reader.readexactly(c)
                    if msg:
                        return msg[:20].rstrip(), msg[20:]
            if not msg:
                return b'pipe_reade_error', b'no data'
        except:
            return b'pipe_reade_error', b''


def pipe_sent_msg(writer, msg_type, msg):
    msg_type = msg_type[:20].ljust(20)
    msg = msg_type + msg
    msg = b'ME' + len(msg).to_bytes(4, byteorder='little') + msg
    writer.write(msg)
    writer.flush()

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]





def key_to_btc_code(h):
    h = b'\x10\x01\xf8' + h
    h += hashlib.sha256(hashlib.sha256(h).digest()).digest()[:4]
    return encode_base58(h)

def key_to_inv_code(h):
    h = b'@\x01\xc9' + h
    h += hashlib.sha256(hashlib.sha256(h).digest()).digest()[:4]
    return encode_base58(h)

def key_to_pmt_code(h):
    h = b'"<$' + h
    h += hashlib.sha256(hashlib.sha256(h).digest()).digest()[:4]
    return encode_base58(h)



def is_address_valid(addr, testnet = False):
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





def is_btc_code_valid(wif):
    if wif[:3] != 'BTC': return False
    h = decode_base58(wif)
    if len(h) != 39:  return False
    checksum = h[-4:]
    if hashlib.sha256(hashlib.sha256(h[:-4]).digest()).digest()[:4] != checksum: return False
    return True

def is_inv_code_valid(wif):
    if wif[:3] != 'inv': return False
    h = decode_base58(wif)
    if len(h) != 39:  return False
    checksum = h[-4:]
    if hashlib.sha256(hashlib.sha256(h[:-4]).digest()).digest()[:4] != checksum: return False
    return True

def is_pmt_code_valid(wif):
    if wif[:3] != 'PMT': return False
    h = decode_base58(wif)
    if len(h) != 39:  return False
    checksum = h[-4:]
    if hashlib.sha256(hashlib.sha256(h[:-4]).digest()).digest()[:4] != checksum: return False
    return True





def sign_message(msg, private_key):
    sign = create_string_buffer(64)

    p= ECDSA.secp256k1_ecdsa_sign(ECDSA_VERIFY_CONTEXT, msg, sign, private_key ,None,None)
    return sign.raw

def sign_message_der(msg, private_key):
    sign = sign_message(msg,private_key)
    signder = create_string_buffer(255)
    s = c_int(255)

    ECDSA.secp256k1_ecdsa_signature_serialize_der(ECDSA_VERIFY_CONTEXT,signder,pointer(s),sign)
    return signder.raw[:s.value]

   





