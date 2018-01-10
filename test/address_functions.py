import unittest
from pybch import tools
from binascii import unhexlify
from pybch import address2hash160


class AddressFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting address functions:\n")

    # def test_pub2segwit(self):
    #     print("pub2segwit")
    #     self.assertEqual(tools.pub2segwit(unhexlify("03db633162d49193d1178a5bbb90bde2f3c196ba0296f010b12a2320a7c6568582")),
    #                      "3PjV3gFppqmDEHjLvqDWv3Y4riLMQg7X1y")


#
# s = "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
# s1 = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
# d = rebase_32_to_5(s)
#
# # print(s)
# # print(d)
# # print(len(d))
# # print(hexlify(d))
#
# PREFIX_TESTNET = "bchtest"
# PREFIX_MAINNET = "bitcoincash"
# b'\x02\t\x14\x03\x0f\t\x0e\x03\x01\x13\x08'
#
# #
# checksum = d[-8:]
# # print("checksum ", hexlify(checksum))
# address = d[:-8]
# # print("address ", hexlify(address))
#
# # address = rebase_32_to_5(address)
# # checksum = rebase_32_to_5(checksum)
# t = bytearray()
# l = b"bitcoincash"
# for i in l:
#     t.append(i&0x1F)
# # print(t)
# t.append(0)
# v = t+address+b"\x00" * 8
#
# #
# # print(v )
# # print("checksum ", hexlify(v))
# # print(hexlify (bech32_polymod(v).to_bytes(5,"big")))
# address = rebase_5_to_8(address, False)
# checksum = rebase_5_to_8(checksum)


#
# print(hexlify(address))
# print(hexlify(checksum))
#
# PREFIX_TESTNET = "bchtest"
# PREFIX_MAINNET = "bitcoincash"
# STRIPPED_PREFIX_MAINNET = b'\x02\t\x14\x03\x0f\t\x0e\x03\x01\x13\x08\x00'
# STRIPPED_PREFIX_TESTNET = b'\x02\x03\x08\x14\x05\x13\x14\x00'
#
# s = 'bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq'
# s.upper()
# print(is_address_valid(s))
# print(is_address_valid('bitcoincash:ppm3qsznhks23z7629mms6s4cwef74vcwvn0h829pq'))
# print(is_address_valid('3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC'))
# print(is_address_valid('1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu'))
#
#
# print(address2hash160('bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq' ,hex = True))
# print(address_type('bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq'))
# print(hash1602address('76a04053bda0a88bda5177b86a15c3b29f559873', p2sh = True))
# print(hash1602address('76a04053bda0a88bda5177b86a15c3b29f559873', legacy = True))
#
#
#
# print(address2hash160(s, True))
# print(address_type(s))




# s = "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
# print(s)
# print(d)
# s2 = encode_base32(d)
#
# print(s2)
#
# vb = d[0]
# length =int((hash_size_map[vb & 0b111] + 8 + 40))
# l = len(s)*5
# print("lenght:", length)
# print("lenght2:", l)
# checksum = d[21:]
# print("checksum length ",len(checksum))
# print(bin(int(hexlify(checksum),16)))
#
# print(bin(vb))
# #print(s2)