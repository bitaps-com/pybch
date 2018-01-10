import unittest
from pybch import *
from binascii import unhexlify
from pybch import address2hash160

class SighashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting sighash:\n")
    def test_sighash_segwit(self):
        """
        	["raw_transaction, script, input_index, hashType, signature_hash (result)"],
        :return: 
        """
        # print("\nNative P2WPKH")
        # raw_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
        # self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_ALL,
        #                                                                  1,
        #                                                                 "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac",
        #                                                                 600000000,
        #                                                                 True)),
        #                  "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")