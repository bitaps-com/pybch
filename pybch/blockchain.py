import io
import json
import math
from .opcodes import *
from .tools import *
from .consensus import *
from binascii import hexlify, unhexlify

def get_stream(stream):
    if type(stream) != io.BytesIO:
        if type(stream) == str:
            stream = unhexlify(stream)
        if type(stream) == bytes:
            stream = io.BytesIO(stream)
        else:
            raise TypeError
    return stream

class Opcode():
  """ Class opcode """
  def __init__(self, raw_opcode, data, data_length = b""):
    self.raw     = raw_opcode
    if self.raw in RAW_OPCODE:
        if self.raw in (OPCODE["OP_PUSHDATA1"], OPCODE["OP_PUSHDATA2"], OPCODE["OP_PUSHDATA4"]):
            self.str = '<%s>' % len(data)
        else:  
            self.str = RAW_OPCODE[self.raw]
    elif self.raw < b'L':
      self.str = '<%s>' % len(data)
    else:
      self.str = '[?]'
    self.data = data
    self.data_length = data_length

  def __str__(self):
    return self.str

  @classmethod
  def to_raw(cls, name):
    if name in OPCODE:
      return OPCODE[name]
    else:
      return b''

  @classmethod
  def pop_from_stream (cls, stream):
    b = stream.read(1)
    if not b: return None
    data = b''
    data_length = b''
    if b <= OPCODE["OP_PUSHDATA4"]:
      if b < OPCODE["OP_PUSHDATA1"]: s = int.from_bytes(b,'little')
      elif b == OPCODE["OP_PUSHDATA1"]: 
        data_length = stream.read(1)
        s = int.from_bytes( data_length ,'little')
      elif b == OPCODE["OP_PUSHDATA2"]: 
        data_length = stream.read(2)
        s = int.from_bytes( data_length ,'little')
      elif b == OPCODE["OP_PUSHDATA4"]: 
        data_length = stream.read(4)
        s = int.from_bytes( data_length ,'little')
      data = stream.read(s)
      if len(data)!=s: 
        return None
        raise Exception('opcode read error')
    return cls(b,data,data_length)



class Script():
    """ 
    Bitcoin script class 
    """
    def __init__(self, raw_script, coinbase = False):
        if type(raw_script) == str:
            raw_script = unhexlify(raw_script)
        self.raw = raw_script
        stream = io.BytesIO(raw_script)
        self.script = []
        self.address = list()
        self.pattern = bytearray()
        self.asm = bytearray()
        self.data = b''
        self.type = "NON_STANDARD"
        self.ntype = 7
        self.op_sig_count = 0
        if coinbase:
            self.pattern = b"<coinbase>"
            self.asm = hexlify(raw_script).decode()
            return
        t = time.time()
        while True:
            o = Opcode.pop_from_stream(stream)
            if o is None:
                break
            if o.raw == OPCODE["OP_CHECKSIG"] or o.raw == OPCODE["OP_CHECKSIGVERIFY"]:
                self.op_sig_count += 1
            if o.raw  ==OPCODE["OP_CHECKMULTISIG"]:
                self.op_sig_count += 20
            self.script.append(o)
            self.pattern += o.str.encode() + b' '
            if o.data:
                self.asm += hexlify(o.data) + b' '
            else:
                self.asm += o.str.encode() + b' '
        self.asm = self.asm.decode().rstrip()
        self.pattern= self.pattern.decode().rstrip()
        # check script type
        if self.pattern == "OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG":
            self.type = "P2PKH"
            self.ntype = 0
            self.address.append(self.script[2].data)
        elif self.pattern == "OP_HASH160 <20> OP_EQUAL":
            self.type = "P2SH"
            self.ntype = 1
            self.address.append(self.script[1].data)
        elif self.pattern == "<65> OP_CHECKSIG" or self.pattern == "<33> OP_CHECKSIG" :
            self.type = "PUBKEY"
            self.ntype = 2
            self.address.append(hash160(self.script[0].data))
        elif len(self.script) == 2 and self.script[0].raw == OPCODE["OP_RETURN"]:
            # OP_RETURN
            if len(self.script[1].data) < NULL_DATA_LIMIT: # <0 to 80 bytes of data>
                self.data = self.script[1].data
                self.type = "NULL_DATA"
                self.ntype = 3
        elif len(self.script)>= 4:
            if self.script[-1].raw == OPCODE["OP_CHECKMULTISIG"] \
                    and self.script[-2].raw <= OPCODE["OP_15"] \
                    and self.script[-2].raw >= OPCODE["OP_1"] : #  OP_CHECKMULTISIG   "OP_1"  "OP_16"
                if self.script[0].raw <= OPCODE["OP_15"] \
                        and self.script[0].raw >= OPCODE["OP_1"]:
                    self.op_sig_count = 0
                    for o in self.script[1:-2]:
                        if not o.data:
                            self.op_sig_count = 20
                            break
                        self.op_sig_count += 1
                        self.address.append(hash160(o.data))
                    else:
                        self.bare_multisig_accepted = ord(self.script[0].raw) - 80
                        self.bare_multisig_from = ord(self.script[-2].raw) - 80
                        self.type = "MULTISIG"
                        self.ntype = 4




class Input:
    """ Transaction Input class """
    #  outpoint = (b'00f0f09...',n')
    #  script   = raw bytes 
    #  sequense = int 
    def __init__(self, outpoint, script, sequence, amount = None, private_key = None):
        if type(outpoint[0]) == str:
            outpoint = (unhexlify(outpoint[0])[::-1], outpoint[1])
        if type(outpoint[0]) == str:
            private_key = WIF2priv(private_key)
        self.outpoint = outpoint
        self.sequence = sequence
        self.pk_script = None
        self.amount = amount
        self.private_key = private_key
        self.p2sh_type = None
        self.coinbase = False
        if outpoint == (b'\x00'*32 ,0xffffffff): self.coinbase = True
        self.sig_script = Script(script, self.coinbase)
        self.double_spend = None
        self.lock = False
        self.addresses = []
        self.redeem_script = None
        if len(self.sig_script.script) > 0:
            try:
                if len(self.sig_script.script[-1].data) <= 520:
                    self.redeem_script = Script(self.sig_script.script[-1].data)
                else:
                    pass
            except Exception as err:
                pass

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        outpoint = stream.read(32), int.from_bytes(stream.read(4), 'little')
        script_len = from_var_int(read_var_int(stream))
        script = stream.read(script_len)
        sequence = int.from_bytes(stream.read(4), 'little')
        return cls(outpoint, script, sequence)


class Output:
    """ Transactin output class """
    def __init__(self, value, script):
        self.value = value
        self.pk_script = Script(script)

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        value = int.from_bytes(stream.read(8), 'little')
        script_len = from_var_int(read_var_int(stream))
        pk_script = stream.read(script_len)
        return cls(value, pk_script)


class Transaction():
    def __init__(self, version, tx_in, tx_out, lock_time,
                 hash=None, size = 0, timestamp = None):
        self.hash = hash
        self.valid = True
        self.lock = False
        self.orphaned = False
        self.in_sum = None
        self.tx_fee = None
        self.version = version
        self.tx_in_count = len(tx_in)
        self.tx_in = tx_in
        self.tx_out_count = len (tx_out)
        self.tx_out = tx_out
        self.lock_time = lock_time
        if self.tx_in:
            self.coinbase = self.tx_in[0].coinbase
        else:
            self.coinbase = False
        self.double_spend = 0
        self.data = None
        self.ip = None
        self.size = size
        if timestamp is not None : self.timestamp = timestamp
        else: self.timestamp = int(time.time())
        self.op_sig_count = 0
        self.sum_value_age = 0
        self.total_outs_value = 0
        for i in self.tx_out:
            self.op_sig_count += i.pk_script.op_sig_count
            if i.pk_script.type=="NULL_DATA":
                self.data = i.pk_script.data
        for out in self.tx_out:
            self.total_outs_value += out.value
        if hash is None:
            self.recalculate_txid()

    def recalculate_txid(self):
        self.hash = double_sha256(self.serialize())


    def add_input(self, tx_hash, output_number,
                  sequence = 0xffffffff,
                  sig_script = b"",
                  amount = None,
                  private_key = None):
        self.tx_in.append(Input((tx_hash, output_number), sig_script, sequence, amount, private_key))
        self.tx_in_count += 1
        self.recalculate_txid()

    def add_P2SH_output(self, amount, p2sh_address):
        if type(p2sh_address)==str:
            p2sh_address = decode_base58(p2sh_address)[1:-4]
        if len(p2sh_address) != 20:
            raise Exception("Invalid output hash160")
        self.tx_out.append(Output(amount,
                           OPCODE["OP_HASH160"] + b'\x14' + p2sh_address + OPCODE["OP_EQUAL"]))
        self.tx_out_count += 1
        self.recalculate_txid()

    def add_P2PKH_output(self, amount, p2pkh_address):
        if type(p2pkh_address)==str:
            p2pkh_address = decode_base58(p2pkh_address)[1:-4]
        if len(p2pkh_address) != 20:
            raise p2pkh_address("Invalid output hash160")
        self.tx_out.append(Output(amount,
                           OPCODE["OP_DUP"] + OPCODE["OP_HASH160"] + b'\x14' + \
                           p2pkh_address + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]))
        self.tx_out_count += 1
        self.recalculate_txid()




    def __str__(self):
        return 'Transaction object [%s] [%s]'% (hexlify(self.hash[::-1]),id(self))


    def serialize(self, hex = False):
        version = self.version.to_bytes(4,'little')
        ninputs = to_var_int(self.tx_in_count)
        inputs = []
        for number, i in enumerate(self.tx_in):
            input = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
            input += to_var_int(len(i.sig_script.raw)) + i.sig_script.raw
            input += i.sequence.to_bytes(4,'little')
            inputs.append(input)
        nouts = to_var_int(self.tx_out_count)
        outputs = []
        for number, i in enumerate(self.tx_out):
            outputs.append(i.value.to_bytes(8,'little')+to_var_int(len(i.pk_script.raw))+i.pk_script.raw)
        result = version + ninputs + b''.join(inputs) +\
            nouts + b''.join(outputs)  + self.lock_time.to_bytes(4,'little')
        if hex:
            return hexlify(result).decode()
        else:
            return result

    def sign_P2PKH_input(self, sighash_type, input_index, compressed, private_key = None):
        if private_key is not None:
            self.tx_in[input_index].private_key = private_key
        else:
            private_key = self.tx_in[input_index].private_key
        pubkey = priv2pub(private_key, compressed)
        pubkey_hash160 = hash160(pubkey)
        scriptCode = OPCODE["OP_DUP"] + OPCODE["OP_HASH160"] + b'\x14' + \
                     pubkey_hash160 + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]
        sighash = self.sighash(sighash_type, input_index, scriptCode)
        signature = sign_message_der(sighash, private_key) + sighash_type.to_bytes(1, 'little')
        sig_script = len(signature).to_bytes(1, 'little') + signature + \
                     len(pubkey).to_bytes(1, 'little') + pubkey
        self.tx_in[input_index].sig_script = Script(sig_script)
        self.recalculate_txid()

    def sighash(self, sighash_type, input_index, scriptCode, amount, hex = False):
        sighash_type = sighash_type | SIGHASH_FORKID
        if type(scriptCode) == str:
         scriptCode = unhexlify(scriptCode)
        if len(self.tx_in) - 1 < input_index:
            raise Exception('Input not exist')
        preimage = bytearray()
        hashPrevouts = bytearray()
        hashSequence = bytearray()
        hashOutputs = bytearray()


        if ((sighash_type & 31) != SIGHASH_ANYONECANPAY):
            for i in self.tx_in:
                hashPrevouts += i.outpoint[0] + int(i.outpoint[1]).to_bytes(4, 'little')
            hashPrevouts = double_sha256(hashPrevouts)
        else:
            hashPrevouts = b'\x00'*32

        if ((sighash_type & 31) != SIGHASH_ANYONECANPAY) and \
           ((sighash_type & 31) != SIGHASH_SINGLE) and \
           ((sighash_type & 31) != SIGHASH_NONE):
            for i in self.tx_in:
                hashSequence += int(i.sequence).to_bytes(4, 'little')
            hashSequence = double_sha256(hashSequence)
        else:
            hashSequence = b'\x00'*32

        if ((sighash_type & 31) != SIGHASH_SINGLE) and \
           ((sighash_type & 31) != SIGHASH_NONE):
            for i in self.tx_out:
                hashOutputs += i.value.to_bytes(8, 'little') + to_var_int(len(i.pk_script.raw)) + i.pk_script.raw
                hashOutputs = double_sha256(hashOutputs)
        elif ((sighash_type & 31) != SIGHASH_SINGLE) and input_index< len(self.tx_out):
            i = self.tx_out[input_index]
            hashOutputs = double_sha256(i.value.to_bytes(8, 'little') + to_var_int(len(i.pk_script.raw)) + i.pk_script.raw)
        else:
            hashOutputs = b'\x00' * 32

        preimage = int(self.version).to_bytes(4, 'little')
        preimage += hashPrevouts
        preimage += hashSequence
        preimage += self.tx_in[input_index].outpoint[0]
        preimage += int(self.tx_in[input_index]).to_bytes(4, 'little')
        preimage += to_var_int(len(scriptCode)) + scriptCode
        preimage += int(amount).to_bytes(8, 'little')
        preimage += int(self.tx_in[input_index].sequence).to_bytes(4, 'little')
        preimage += hashOutputs
        preimage += self.lock_time.to_bytes(4, 'little')
        preimage += int(sighash_type).to_bytes(4, 'little')
        return double_sha256(preimage) if not hex else hexlify(double_sha256(preimage)).decode()



    def json(self):
        r = dict()
        r["txid"] = rh2s(self.hash)
        r["size"] = self.size
        r["version"] = self.version
        r["locktime"] = self.lock_time
        r["vin"] = list()
        r["vout"] = list()
        for i in self.tx_in:
            input = {"txid": rh2s(i.outpoint[0]),
                     "vout": i.outpoint[1],
                     "scriptSig": {"hex": hexlify(i.sig_script.raw).decode(),
                                   "asm": i.sig_script.asm},
                     "sequence": i.sequence}
            if i.coinbase:
                input["coinbase"] = hexlify(i.sig_script.raw).decode()
            r["vin"].append(input)
        for index, o in enumerate(self.tx_out):
            out = {"value": o.value,
                   "n": index,
                   "scriptPubKey": {"hex": hexlify(o.pk_script.raw).decode()},
                                    "asm": o.pk_script.asm,
                                    "type": o.pk_script.type}
            r["vout"].append(out)

        return json.dumps(r)



    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        raw_tx = bytearray()
        raw_wtx = bytearray()
        start = stream.tell()
        version = int.from_bytes(stream.read(4), 'little')
        tx_in = read_var_list(stream, Input)
        tx_out = read_var_list(stream, Output)
        lock_time = int.from_bytes(stream.read(4), 'little')
        size = stream.tell()
        stream.seek(start)
        data = stream.read(size)
        tx_id = double_sha256(data)
        return cls(version, tx_in, tx_out, lock_time,
                   hash = tx_id, size = size)


class Block():
    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce, txs, block_size,hash=None):
        self.hash = hash
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.txs = txs
        self.block_size = block_size
        self.height = None
        self.id = None
        self.chain = None
        self.amount = 0
        self.mountpoint = None
        self.side_branch_set = None
        self.tx_hash_list = list()
        self.op_sig_count = 0
        for t in txs:
            if t.hash in txs:
                raise Exception("CVE-2012-2459") # merkle tree malleability
            self.op_sig_count += t.op_sig_count
            self.tx_hash_list.append(t.hash)
        self.target = None
        self.fee = 0

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        header = stream.read(80)
        stream.seek(-80, 1)
        kwargs = {
            'hash': hashlib.sha256(hashlib.sha256(header).digest()).digest(),
            'version': int.from_bytes(stream.read(4), 'little'),
            'prev_block': stream.read(32),
            'merkle_root': stream.read(32),
            'timestamp': int.from_bytes(stream.read(4), 'little'),
            'bits': int.from_bytes(stream.read(4), 'little'),
            'nonce': int.from_bytes(stream.read(4), 'little'),
            'txs': read_var_list(stream, Transaction),
            'block_size': stream.tell()
        }
        return cls(**kwargs)

