import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)
import bitcoinlib
import io
import json
from binascii import hexlify, unhexlify


print(bitcoinlib.version)


# body = b'\x01\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff#\x038\x9b\x11\x00\xfe\xc6&mY\xfe\x04\xf0\x01\x00\tcgminer42\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x02%\xcf[\t\x00\x00\x00\x00\x19v\xa9\x14K\xfe\x90\xc8\xe6\xc65,\x03K?W\xd5\n\x9anw\xa6*\x07\x88\xac\x00\x00\x00\x00\x00\x00\x00\x00&j$\xaa!\xa9\xed\x9dbR\x19\x81\x8c\x83\xfd.s\xf3\xc4\x00\t\xe8$\xfeJ\x91X\x0cN$3\xa7\x1a\xa6\xb1\xcf[\xcb\xf9\x01 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
body = unhexlify("010000000185a0c767cc7c2da3899d9574f7f3f13522b19573b64b070800af6ae3c15a5ba2010000006b483045022100d3bac9c52c523f4202f001f9d6bef3763a1f01329b41b3d275392613d36483a0022052b264637b83c5c24d4ec67f26d0597896e111c17d1d11b45808a8cae2b40b6a012102f006b07d3a2f5649488ed91324fc9a852ef4e5c554a60d0b74f1e58771094b33ffffffff0280a4bf07000000001976a914eab902dff81deb245ed28d092b1848bbf223608288aca6cb9600000000001976a914510ed61fd3b33344c9b232635d2fb5cf1a96ec6088ac00000000")
# print(len(body))
import hashlib

# print(bitcoinlib.rh2s(hashlib.sha256(hashlib.sha256(body).digest()).digest()))
p = bitcoinlib.Transaction.deserialize(io.BytesIO(body))
parsed = json.loads(p.json())
print(json.dumps(parsed, indent=4, sort_keys=True))
