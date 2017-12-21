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
    def __init__(self, raw_script, coinbase = False, segwit = True):
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

        elif segwit:
            if self.pattern == "OP_0 <20>":
                self.type = "P2WPKH"
                self.op_sig_count = 1
                self.ntype = 5
                self.address.append(b"\x00"+self.script[1].data)
            elif self.pattern == "OP_0 <32>":
                self.type = "P2WSH"
                self.ntype = 6
                self.address.append(b"\x00"+self.script[1].data)



class Input:
    """ Transaction Input class """
    #  outpoint = (b'00f0f09...',n')
    #  script   = raw bytes 
    #  sequense = int 
    def __init__(self, outpoint, script, sequence):
        self.outpoint = outpoint
        self.sequence = sequence
        self.pk_script = None
        self.amount = None
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

class Witness:
    def __init__(self, data, empty = False):
        self.empty = empty
        self.witness = [b"\x00"] if empty else data

    def __str__(self):
        return json.dumps([binascii.hexlify(w).decode() for w in self.witness])

    def hex(self):
        return [binascii.hexlify(w).decode() for w in self.witness]

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        empty = True
        witness_len = from_var_int(read_var_int(stream))
        witness = []
        if witness_len:
            for i in range(witness_len):
                l = from_var_int(read_var_int(stream))
                w = stream.read(l)
                witness.append(w)
            empty = False
        return cls(witness, empty)

    def serialize(self):
        if self.empty:
            return b'\x00'

        n = to_var_int(len(self.witness))
        for w in self.witness:
            n += to_var_int(len(w)) + w
        return n


class Transaction():
    def __init__(self, version, tx_in, tx_out, lock_time,
                 hash=None, size = 0, timestamp = None,
                 marker = None, flag = None, witness = None,
                 whash = None, vsize = None):
        self.hash = hash
        self.whash = whash
        self.vsize = vsize
        self.witness = witness
        self.marker = marker
        self.flag = flag
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
        self.coinbase = self.tx_in[0].coinbase
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
        if witness is None:
            self.witness = [Witness.deserialize(b"\x00") for i in range(len(tx_in))]


    def __str__(self):
        return 'Transaction object [%s] [%s]'% (hexlify(self.hash[::-1]),id(self))


    def serialize(self, segwit = False, hex = False):
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
        marke_flag = b"\x00\x01" if segwit else b""
        witness = b""
        if segwit:
            for w in self.witness:
                witness += w.serialize()
        result = version + marke_flag + ninputs + b''.join(inputs) +\
            nouts + b''.join(outputs) + witness + self.lock_time.to_bytes(4,'little')
        if hex:
            return hexlify(result).decode()
        else:
            return result

    def sign_P2SHP2WPKH_input(self, sighash_type, input_index, amount, private_key):
        if type(private_key) == str:
            private_key = WIF2priv(private_key)
        pubkey = priv2pub(private_key, True)
        pubkey_hash160 = hash160(pubkey)
        scriptCode  = b"\x19" + OPCODE["OP_DUP"] + OPCODE["OP_HASH160"]
        scriptCode += b'\x14' + pubkey_hash160 + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]
        self.tx_in[input_index].sig_script = Script(b'\x16\x00\x14' + pubkey_hash160) # P2WPKHredeemScript
        sighash = self.sighash_segwit(sighash_type, input_index, scriptCode, amount)
        signature = sign_message_der(sighash, private_key) + sighash_type.to_bytes(1,'little')
        self.witness[input_index] = Witness([signature, pubkey])

    def sighash(self, sighash_type, input_index, scriptCode, hex = False):
        if type(scriptCode) == str:
         scriptCode = unhexlify(scriptCode)
        if self.tx_in_count-1 < input_index:
            raise Exception('Input not exist')
        preimage = bytearray()
        if ((sighash_type&31) == SIGHASH_SINGLE) and (input_index>(len(self.tx_out)-1)):
            return double_sha256(b'\x01'+b'\x00'*31 + sighash_type.to_bytes(4, 'little'))
        preimage += self.version.to_bytes(4,'little')
        preimage += b'\x01' if sighash_type &  SIGHASH_ANYONECANPAY else to_var_int(self.tx_in_count)
        for number, i in enumerate(self.tx_in):
            if (sighash_type &  SIGHASH_ANYONECANPAY) and (input_index != number): continue
            input = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
            if sighash_type == 0 or input_index == number:
                input += ((to_var_int(len(scriptCode)) + scriptCode) if sighash_type else \
                (to_var_int(len(i.sig_script.raw)) + i.sig_script.raw)) + i.sequence.to_bytes(4,'little')
            else:
                input += b'\x00' + (i.sequence.to_bytes(4,'little') if \
                ((sighash_type&31) == SIGHASH_ALL) else b'\x00\x00\x00\x00')
            preimage += input
        preimage += b'\x00' if (sighash_type&31) == SIGHASH_NONE else ( to_var_int(input_index + 1) if \
            (sighash_type&31) == SIGHASH_SINGLE else to_var_int(self.tx_out_count))
        if  (sighash_type&31) != SIGHASH_NONE:
            for number, i in enumerate(self.tx_out):
                if number > input_index and (sighash_type&31) == SIGHASH_SINGLE: continue
                preimage +=(b'\xff'*8+b'\x00' if (sighash_type&31) == SIGHASH_SINGLE and (input_index != number)\
                else i.value.to_bytes(8,'little')+to_var_int(len(i.pk_script.raw))+i.pk_script.raw)
        preimage += self.lock_time.to_bytes(4,'little')
        preimage += sighash_type.to_bytes(4, 'little')
        return double_sha256(preimage) if not hex else hexlify(double_sha256(preimage)).decode()


    def sighash_segwit(self, sighash_type, input_index, scriptCode, amount, hex = False):
        if type(scriptCode) == str:
            scriptCode = unhexlify(scriptCode)
        if self.tx_in_count-1 < input_index:
            raise Exception('Input not exist')
        preimage = bytearray()
        # 1. nVersion of the transaction (4-byte little endian)
        preimage += self.version.to_bytes(4,'little')
        # 2. hashPrevouts (32-byte hash)
        # 3. hashSequence (32-byte hash)
        # 4. outpoint (32-byte hash + 4-byte little endian)
        # 5. scriptCode of the input (serialized as scripts inside CTxOuts)
        # 6. value of the output spent by this input (8-byte little endian)
        # 7. nSequence of the input (4-byte little endian)
        hp = bytearray()
        hs = bytearray()
        for n, i in enumerate(self.tx_in):
            if not (sighash_type & SIGHASH_ANYONECANPAY):
                hp += i.outpoint[0] + i.outpoint[1].to_bytes(4,'little')
                if (sighash_type&31) != SIGHASH_SINGLE and (sighash_type&31) != SIGHASH_NONE:
                    hs += i.sequence.to_bytes(4,'little')
            if n == input_index:
                outpoint = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
                nSequence = i.sequence.to_bytes(4,'little')
        hashPrevouts = double_sha256(hp) if hp else b'\x00'*32
        hashSequence = double_sha256(hs) if hs else b'\x00'*32
        value = amount.to_bytes(8,'little')
        # 8. hashOutputs (32-byte hash)
        ho = bytearray()
        for n, i in enumerate(self.tx_out):
            if  (sighash_type&31) != SIGHASH_SINGLE  and  (sighash_type&31) != SIGHASH_NONE:
                ho += i.value.to_bytes(8,'little')+to_var_int(len(i.pk_script.raw))+i.pk_script.raw
            elif (sighash_type&31) == SIGHASH_SINGLE and input_index < len(self.tx_out):
                if input_index == n:
                    ho += i.value.to_bytes(8, 'little') + to_var_int(len(i.pk_script.raw)) + i.pk_script.raw
        hashOutputs = double_sha256(ho) if ho else b'\x00'*32
        preimage += hashPrevouts + hashSequence + outpoint + scriptCode + value + nSequence + hashOutputs
        preimage += self.lock_time.to_bytes(4, 'little')
        preimage += sighash_type.to_bytes(4, 'little')
        return double_sha256(preimage) if not hex else hexlify(double_sha256(preimage)).decode()


    def json(self):
        r = dict()
        r["txid"] = rh2s(self.hash)
        r["wtxid"] = r["txid"] if self.whash is None else rh2s(self.whash)
        r["size"] = self.size
        r["vsize"] = self.vsize
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
        if self.witness is not None:
            for index, w in enumerate(self.witness):
                r["vin"][index]["witness"] = w.hex()
        for index, o in enumerate(self.tx_out):
            out = {"value": o.value,
                   "n": index,
                   "scriptPubKey": {"hex": hexlify(o.pk_script.raw).decode()},
                                    "asm": o.pk_script.asm,
                                    "type": o.pk_script.type}
            r["vout"].append(out)

        return json.dumps(r)




    def eval_script(self, input_index, script, _stack = None):
        script = list(script)
        #print("debug version")
        if _stack is None: stack = []
        else: stack = _stack
        altstack = list()
        level = 0
        escript= []
        executed = 0

        while True:
            # print("%s stack: %s" % (executed,str(list(map(binascii.hexlify,stack)))))
            if executed > MAX_OPS_PER_SCRIPT: return  False,'>MAX_OPS_PER_SCRIPT opcodes executed'
            if len(stack)+len(altstack)> 1000: return  False,'>1,000 stack size'
            if len(script) == 0 : break
            opcode = script.pop(0)
            # print("opcode :%s"%  str(opcode) )
            if opcode.data == b'':  executed += 1
            escript.append(opcode)
            # process execution flow opcodes
            if opcode.raw == OPCODE["OP_NOP"]:  continue
            if opcode.raw == OPCODE["OP_IF"] or opcode.raw == OPCODE["OP_NOTIF"] :
                level += 1
                t = b2i(stack.pop())
                if t != 0 : t = 1
                # print(">>>>>>>>>>>")
                # print(t)
                m = 0 if opcode.raw == OPCODE["OP_IF"] else 1
                if t == m: # seek to else or end/if/notif in case condition is not match
                    tl = level
                    try:
                        while True:
                            opcode = script.pop(0)
                            escript.append(opcode)
                            if len(opcode.data)> MAX_SCRIPT_ELEMENT_SIZE: return  False,' >MAX_SCRIPT_ELEMENT_SIZE byte push'
                            if opcode.data == b'' and opcode.raw!= OPCODE["OP_RESERVED"]: executed +=1
                            if opcode.raw in ( OPCODE["OP_VERIF"], OPCODE["OP_VERNOTIF"],): return  False,'%s disabled opcode 3' % opcode.str
                            if opcode.raw in ( OPCODE["OP_INVALIDOPCODE"], OPCODE["OP_PUBKEY"], OPCODE["OP_PUBKEYHASH"], OPCODE["OP_RETURN"], OPCODE["OP_RESERVED"], OPCODE["OP_VER"], OPCODE["OP_RESERVED1"], OPCODE["OP_RESERVED2"]) : continue
                            if opcode.raw in DISABLED_OPCODE: return  False,'%s disabled opcode 2' % opcode.str
                            if opcode.raw == OPCODE["OP_IF"] or opcode.raw == OPCODE["OP_NOTIF"] : level+=1
                            if opcode.raw == OPCODE["OP_ENDIF"]: level -= 1
                            if opcode.raw == OPCODE["OP_ELSE"] and tl == level: break
                            if tl > level: break
                        continue
                    except Exception as err:
                        return False,'if block error %s' % err
            if  opcode.raw == OPCODE["OP_ENDIF"]:
                level -= 1
                if level >= 0: continue
                else: return False,'endif block without if/ifnot'

            if  opcode.raw == OPCODE["OP_ELSE"]: # seek to endif
                if level == 0 : return False,'else block error '
                tl = level
                try:
                    while True:
                        opcode = script.pop(0)
                        escript.append(opcode)
                        if len(opcode.data)> 520: return  False,' >520 byte push'
                        if opcode.data == b'' and opcode.raw!= OPCODE["OP_RESERVED"]: executed +=1
                        if opcode.raw in ( OPCODE["OP_INVALIDOPCODE"],  OPCODE["OP_PUBKEY"], OPCODE["OP_PUBKEYHASH"], OPCODE["OP_RETURN"], OPCODE["OP_RESERVED"], OPCODE["OP_VER"], OPCODE["OP_RESERVED1"], OPCODE["OP_RESERVED2"]) : continue
                        #if opcode.raw in ( OPCODE["VERIF"],): return  False,'%s disabled opcode 3' % opcode.str
                        if opcode.raw in ( OPCODE["OP_VERIF"], OPCODE["OP_VERNOTIF"],): return  False,'%s disabled opcode 3' % opcode.str
                        if opcode.raw in DISABLED_OPCODE: return  False,'%s disabled opcode 1' % opcode.str
                        if opcode.raw == OPCODE["OP_IF"] or opcode.raw == OPCODE["OP_NOTIF"] : level+=1
                        if opcode.raw == OPCODE["OP_ENDIF"]: level -= 1
                        if opcode.raw == OPCODE["OP_ELSE"] and tl == level: break
                        if tl > level: break
                    continue
                except Exception as err: return False,'else block error %s' % err

            if opcode.raw == OPCODE["OP_VERIFY"]:
                if b2i(stack.pop()) == False: return  False,'vp stack is False'
            if  opcode.raw == OPCODE["OP_RETURN"]: return  False,'OP_RETURN top stack is False'

            if opcode.raw in DISABLED_OPCODE or opcode.raw == OPCODE['OP_VER']: return  False,'%s disabled opcode 1' % opcode.str
            if opcode.raw <= OPCODE["OP_16"]:
                if opcode.raw <= OPCODE["OP_PUSHDATA4"]:
                    if len(opcode.data)> 520: return  False,' >520 byte push'
                    stack.append(opcode.data)  # push to stack
                else: stack.append ( i2b(b2i(opcode.raw) - 80) )
                continue

            elif opcode.raw <= OPCODE["OP_TUCK"]: # stack
                if opcode.raw == OPCODE["OP_TOALTSTACK"]:  altstack.append(stack.pop())
                elif  opcode.raw == OPCODE["OP_FROMALTSTACK"]:  stack.append(altstack.pop())
                elif  opcode.raw == OPCODE["OP_IFDUP"]:
                    if stack[-1]: stack.append(stack[-1])
                elif  opcode.raw == OPCODE["OP_DEPTH"]:  stack.append(i2b(len(stack)))
                elif  opcode.raw == OPCODE["OP_DROP"]:  stack.pop()
                elif  opcode.raw == OPCODE["OP_DUP"]:  stack.append(stack[-1])
                elif  opcode.raw == OPCODE["OP_NIP"]:
                    t = stack.pop()
                    stack.pop()
                    stack.append(t)
                elif  opcode.raw == OPCODE["OP_OVER"]: stack.append(stack[-2])
                elif  opcode.raw == OPCODE["OP_PICK"]:
                    a = b2i(stack.pop())
                    if a < 0 : return  False,'OP_PICK index negative'
                    stack.append(stack[-a-1])
                elif  opcode.raw == OPCODE["OP_ROLL"]:
                    a = b2i(stack.pop())
                    if a < 0 : return  False,'OP_ROLL index negative'
                    stack.append(stack.pop(-a-1))
                elif  opcode.raw == OPCODE["OP_ROT"]: stack.append(stack.pop(-3))
                elif  opcode.raw == OPCODE["OP_SWAP"]: stack.append(stack.pop(-2))
                elif  opcode.raw == OPCODE["OP_TUCK"]:
                    v1 = stack.pop()
                    v2 = stack.pop()
                    stack.append(v1)
                    stack.append(v2)
                    stack.append(v1)
                elif  opcode.raw == OPCODE["OP_2DROP"]:
                    stack.pop()
                    stack.pop()
                elif  opcode.raw == OPCODE["OP_2DUP"]:
                    stack.append(stack[-2])
                    stack.append(stack[-2])
                elif  opcode.raw == OPCODE["OP_3DUP"]:
                    stack.append(stack[-3])
                    stack.append(stack[-3])
                    stack.append(stack[-3])
                elif  opcode.raw == OPCODE["OP_2OVER"]:
                    stack.append(stack[-4])
                    stack.append(stack[-4])
                elif  opcode.raw == OPCODE["OP_2ROT"]:
                    stack.append(stack.pop(-6))
                    stack.append(stack.pop(-6))
                elif  opcode.raw == OPCODE["OP_2SWAP"]:
                    stack.append(stack.pop(-4))
                    stack.append(stack.pop(-4))

            elif opcode.raw <= OPCODE["OP_EQUALVERIFY"]: # Bitwise logic and splice
                if  opcode.raw == OPCODE["OP_SIZE"]: stack.append(i2b(len(stack[-1]) ))
                elif  opcode.raw == OPCODE["OP_EQUAL"]:
                    x1 = stack.pop()
                    x2 = stack.pop()
                    # if x1 == b'': x1 = b'\x01'

                    # print(x1)
                    # print(x2)
                    stack.append(b'\x01' if x1 == x2 else b'' )

                elif  opcode.raw == OPCODE["OP_EQUALVERIFY"]:
                    x1 = stack.pop()
                    x2 = stack.pop()
                    stack.append(b'\x01' if x1 == x2 else b'' )
                    if b2i(stack.pop()) == False: return  False,'OP_VERIFY top stack is False'


            elif opcode.raw <= OPCODE["OP_WITHIN"]: # Arithmetic
                if b2i(stack[-1]) >= 2147483648  or b2i(stack[-1]) <= -2147483648 : return  False,'arithmetic operands must be in range [-2^31...2^31]'
                if  opcode.raw == OPCODE["OP_1ADD"]:     stack[-1] =     i2b(b2i(stack[-1])+1)
                elif  opcode.raw == OPCODE["OP_1SUB"]:   stack[-1] =     i2b(b2i(stack[-1])-1)
                elif  opcode.raw == OPCODE["OP_NEGATE"]: stack[-1] =     i2b( -1 * b2i(stack[-1]))
                elif  opcode.raw == OPCODE["OP_ABS"]: stack[-1] =        i2b(abs(b2i(stack[-1])))
                elif  opcode.raw == OPCODE["OP_NOT"]: stack[-1] =        i2b(int(0 == abs(b2i(stack[-1]))))
                elif  opcode.raw == OPCODE["OP_0NOTEQUAL"]: stack[-1] =  i2b(int(not 0 == abs(b2i(stack[-1]))))
                else:
                    if b2i(stack[-2]) >= 2147483648  or b2i(stack[-2]) <= -2147483648 : return  False,'arithmetic operands must be in range [-2^31...2^31]'
                if  opcode.raw == OPCODE["OP_ADD"]:
                    a = b2i(stack.pop())
                    b = b2i(stack.pop())
                    c = a+b
                    stack.append( i2b(c))
                elif  opcode.raw == OPCODE["OP_SUB"]: stack.append( i2b( -1 * b2i(stack.pop()) +  b2i(stack.pop()) ))

                elif  opcode.raw == OPCODE["OP_BOOLAND"]:  stack.append(i2b(int((b2i(stack.pop()) != 0) and (b2i(stack.pop()) != 0))))
                elif  opcode.raw == OPCODE["OP_BOOLOR"]:   stack.append(i2b(int((b2i(stack.pop()) != 0) or (b2i(stack.pop()) != 0))))
                elif  opcode.raw == OPCODE["OP_NUMEQUAL"]:
                    a = int(b2i(stack.pop()))
                    b = int(b2i(stack.pop()))
                    stack.append(i2b(int( a == b )))
                elif  opcode.raw == OPCODE["OP_NUMEQUALVERIFY"]:
                    stack.append( i2b( int(b2i(stack.pop())==b2i(stack.pop()))))
                    if b2i(stack.pop()) == False: return  False,'OP_NUMEQUALVERIFY top stack is False'
                elif  opcode.raw == OPCODE["OP_NUMNOTEQUAL"]: stack.append( i2b(int(b2i(stack.pop())!=b2i(stack.pop()))))
                elif  opcode.raw == OPCODE["OP_LESSTHAN"]: stack.append( i2b( int(b2i(stack.pop())>b2i(stack.pop()))))
                elif  opcode.raw == OPCODE["OP_GREATERTHAN"]: stack.append( i2b( int(b2i(stack.pop())<b2i(stack.pop()))))
                elif  opcode.raw == OPCODE["OP_LESSTHANOREQUAL"]: stack.append( i2b( int(b2i(stack.pop())>=b2i(stack.pop()))))
                elif  opcode.raw == OPCODE["OP_GREATERTHANOREQUAL"]: stack.append( i2b( int(b2i(stack.pop())<=b2i(stack.pop()))))

                elif  opcode.raw == OPCODE["OP_MIN"]:
                    a = b2i(stack.pop())
                    b = b2i(stack.pop())
                    if a > b: a = b
                    stack.append(i2b(a))
                elif  opcode.raw == OPCODE["OP_MAX"]:
                    a = b2i(stack.pop())
                    b = b2i(stack.pop())
                    if a < b: a = b
                    stack.append(i2b(a))

                elif  opcode.raw == OPCODE["OP_WITHIN"]:
                    a = b2i(stack.pop())
                    b = b2i(stack.pop())
                    x = b2i(stack.pop())
                    stack.append(i2b(int((x < a) and (x >= b))))


            elif opcode.raw <= OPCODE["OP_CHECKMULTISIGVERIFY"]: # crypto
                if  opcode.raw == OPCODE["OP_RIPEMD160"]: stack.append(ripemd160(stack.pop()))
                elif  opcode.raw == OPCODE["OP_SHA1"]:   stack.append(hashlib.sha1(stack.pop()).digest())
                elif  opcode.raw == OPCODE["OP_SHA256"]: stack.append(hashlib.sha256(stack.pop()).digest())
                elif  opcode.raw == OPCODE["OP_HASH160"]: stack.append(ripemd160(hashlib.sha256(stack.pop()).digest()))
                elif  opcode.raw == OPCODE["OP_HASH256"]: stack.append(double_sha256(stack.pop()))
                elif  opcode.raw == OPCODE["OP_CODESEPARATOR"]: escript= []

                elif  opcode.raw == OPCODE["OP_CHECKSIG"] or opcode.raw == OPCODE["OP_CHECKSIGVERIFY"]:
                    # print(stack)
                    vchPubKey = stack.pop()
                    vchSig    = stack.pop()
                    if not is_valid_signature_encoding(vchSig): raise Exception('signature  invalid')
                    if not is_valid_pub(vchPubKey): raise Exception('pubKey  invalid')
                    subscript = b''
                    # delete OP_CODESEPARATOR and SIGNATURE
                    for o in  escript + script:
                        if o.raw != OPCODE['OP_CODESEPARATOR'] and o.data!=vchSig: 
                            subscript+=o.raw +o.data_length + o.data
                    hashtype = vchSig[-1]
                    # print('hello')
                    # print("signatere type %s " % hashtype)
                    if hashtype == 0 : hashtype = 1
                    # print("lock time:")
                    # print(self.lock_time)
                    #print(binascii.hexlify(self.serialize(hashtype, input_index, subscript)))
                    sigHash = double_sha256(self.serialize(hashtype,input_index, subscript)+int(hashtype).to_bytes(4,'little'))
                    stack.append(i2b(check_sig(vchSig, vchPubKey, sigHash, ECDSA_VERIFY_CONTEXT)))
                    # print(sigHash)
                    # print(rh2s(sigHash))
                    # print(checkSig(vchSig, vchPubKey, sigHash, ECDSA_VERIFY_CONTEXT))
                    # print(checkSig(vchSig, vchPubKey, sigHash, ECDSA_VERIFY_CONTEXT))
                    # print(checkSig(vchSig, vchPubKey, sigHash, ECDSA_VERIFY_CONTEXT))
                    # print(i2b(0))
                    #print(b2i(0))
                    # print(stack)
                    if opcode.raw == OPCODE["OP_CHECKSIGVERIFY"]:
                        # print('opchverf')
                        # print(stack)
                        if b2i(stack.pop()) == False: return  False,'OP_CHECKSIGVERIFY top stack is False'
                elif  opcode.raw == OPCODE["OP_CHECKMULTISIG"] or  opcode.raw == OPCODE["OP_CHECKMULTISIGVERIFY"]:
                    # print("checking")
                    i = 1
                    if len(stack)<i : return  False,'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    nKeysCount = b2i(stack[-i])
                    if nKeysCount < 0 or nKeysCount > MAX_PUBKEYS_PER_MULTISIG: return  False,'SCRIPT_ERR_PUBKEY_COUNT'
                    executed += nKeysCount
                    if executed > MAX_OPS_PER_SCRIPT: return  False,'SCRIPT_ERR_OP_COUNT'
                    i += 1
                    ikey = i
                    i += nKeysCount
                    if len(stack) < i : return  False,'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    nSigsCount = b2i(stack[-i])
                    if nSigsCount < 0 and nSigsCount > nKeysCount:  return  False,'SCRIPT_ERR_SIG_COUNT'
                    i += 1
                    isig = i
                    i += nSigsCount
                    signatures = set()
                    for k in range(nSigsCount):
                        signatures.add(stack[-isig-k])
                    subscript=b''
                    for opcode in escript + script:
                       if opcode.raw != OPCODE['OP_CODESEPARATOR'] and opcode.data not in signatures: 
                        subscript+=opcode.raw + opcode.data_length+opcode.data
                    fSuccess = 1
                    # print(nSigsCount)
                    while nSigsCount > 0:
                        # print('.')
                        vchSig = stack[-isig]
                        vchPubKey = stack[-ikey]
                        # to do bip 66 better implementation
                        if not is_valid_pub(vchPubKey): return False, 'pubKey invalid'
                        if not is_valid_signature_encoding(vchSig): return  False,'signature invalid'
                        # fOk = checkSig(vchSig, vchPubKey, subscript, raw_tx, input_index)
                        hashtype = vchSig[-1]
                        if hashtype == 0 : hashtype = 1
                        #print(binascii.hexlify(self.serialize(hashtype, input_index, subscript)))
                        sigHash = double_sha256(self.serialize(hashtype,input_index, subscript)+int(vchSig[-1]).to_bytes(4,'little'))
                        fOk = check_sig(vchSig, vchPubKey, sigHash, ECDSA_VERIFY_CONTEXT)
                        # print("fok %s" % fOk)
                        if fOk:
                            isig += 1
                            nSigsCount -= 1
                        ikey += 1
                        nKeysCount -= 1
                        # If there are more signatures left than keys left,
                        # then too many signatures have failed. Exit early,
                        # without checking any further signatures.

                        if nSigsCount > nKeysCount:
                            fSuccess = 0
                            break

                    # Clean up stack of actual arguments
                    while i> 1:
                        i -= 1
                        stack.pop()
                    # A bug causes CHECKMULTISIG to consume one extra argument
                    # whose contents were not checked in any way.
                    #
                    # Unfortunately this is a potential source of mutability,
                    # so optionally verify it is exactly equal to zero prior
                    # to removing it from the stack.
                    if len(stack) < 1:  return  False, 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    stack.pop()
                    stack.append(i2b(fSuccess))

                    if  opcode.raw == OPCODE["OP_CHECKMULTISIGVERIFY"] or opcode.raw == OPCODE["OP_CHECKSIGVERIFY"]:
                        if b2i(stack.pop()) == False: return  False,'OP_CHECKMULTISIGVERIFY top stack is False'



            else:
                if opcode.raw>=b'\xb0' and opcode.raw<=b'\xb9' : continue
                return False,'unknown opcode'
        if level > 0 : return False,'endif missing'
        return True,stack



    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        raw_tx = bytearray()
        raw_wtx = bytearray()
        start = stream.tell()
        version = int.from_bytes(stream.read(4), 'little')
        marker = stream.read(1)
        flag =  stream.read(1)
        if marker == b"\x00" and flag ==  b"\x01":
            # segwit format
            point1 = stream.tell()
            tx_in = read_var_list(stream, Input)
            tx_out = read_var_list(stream, Output)
            point2 = stream.tell()
            inputs_count = len(tx_in)
            witness = [Witness.deserialize(stream) for i in range(inputs_count)]
            point3 = stream.tell()
            lock_time = int.from_bytes(stream.read(4), 'little')
            # calculate tx_id hash
            size = stream.tell() - start
            stream.seek(start)
            raw_tx += stream.read(4)
            stream.seek(2,1)
            raw_tx += stream.read(point2 - point1)
            stream.seek(point3-point2, 1)
            raw_tx += stream.read(4)
            tx_id = double_sha256(raw_tx)
            for w in witness:
                if not w.empty:
                    # caluculate wtx_id
                    stream.seek(start)
                    data = stream.read(size)
                    wtx_id = double_sha256(data)
                    break
                else:
                    wtx_id = tx_id
            vsize = math.ceil((len(raw_tx) * 3 + size) / 4)
        else:
            stream.seek(start)
            marker = b"\x00"
            flag = b"\x01"
            version = int.from_bytes(stream.read(4), 'little')
            tx_in = read_var_list(stream, Input)
            tx_out = read_var_list(stream, Output)
            witness = [Witness.deserialize(b"\x00") for i in range(len(tx_in))]
            lock_time = int.from_bytes(stream.read(4), 'little')
            size = stream.tell() - start
            stream.seek(start)
            data = stream.read(size)
            tx_id = double_sha256(data)
            wtx_id = None
            vsize = size

        return cls(version, tx_in, tx_out, lock_time,
                   hash = tx_id, size = size,
                   marker = marker, flag = flag,
                   witness = witness, whash = wtx_id, vsize = vsize)


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

