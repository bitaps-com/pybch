import unittest
from pybch import *
from binascii import unhexlify
from pybch import address2hash160

class SighashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting sighash:\n")
    def test_sighash_segwit(self):
        signed_tx = "010000000142ded4161d8ebd76a96b9a43d80949dce4e7687fea502182e18add378a9324f1000000006a47304402204fa19059397b738b3c5621c4b068d6c65b96d51afca7aedecdd17a9472df0cf202204f92e927b1a6515257649f1ff781d4e67ab03b051cb15d2d7ac8e2f854f17b16412102fabaac18d308a6c22e67dba8e5d666cd0741247958fbe19a62a20c28ed358a70ffffffff01baaa9a00000000001976a9144a43d1d2cecc11f159ea33ae90cc8aa654e7b02788ac00000000"
        priv = "KyhRo54TWv6NkcqcuMZx7vHFQnd8JZLzsy1v4BNKP6AchGs4zFnh"
        address = "mnHdYSSg441N6FRxfjxZzKapgwUp9UaMWE"
        outpoint_hash = "f124938a37dd8ae1822150ea7f68e7e4dc4909d8439a6ba976bd8e1d16d4de42"
        outpoint_index = 0
        amount = 10156250
        tx = Transaction(1, [], [], 0)
        tx.add_input(outpoint_hash, outpoint_index, amount=amount, private_key=priv)
        tx.add_P2PKH_output(amount - 20000, address)
        tx.sign_P2PKH_input(SIGHASH_ALL, 0)
        raw_tx = tx.serialize(hex=True)
        self.assertEqual(raw_tx, signed_tx)