import unittest
from pybch import *
from binascii import unhexlify
from pybch import address2hash160

class SighashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting sighash:\n")
    def test_sign_one_input(self):
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

    def test_sign_multi(self):
        input_list = [{
                       'input_tx_hash': "51956d107442bff53a3f5a7e6bfd86548676911144489ecda67f1b1ff2496ad5",
                       # 81850bd17026b498720dbc9c9b655512f7c35b882aca6f846e8203c9864051be
                       'receiver': '1E2K64b281k5REC1QF66KRUsC5UqmqZamc',
                       'input_out': 0,
                       's': unhexlify("76a9148ed9264f34b3677aba20ba18a50ba4a2fb119dea88ac"),
                       'private_key': "KwJ2eyPgQJ4vtqffTBZXXF5anqqBJxJXkYZD4DmshhF8LKWnx8AK",
                       # KwL4NhhncCQuN94jEs7GxW1uhA8JWQANZ4AHGuif2wB5zwsmNVLM
                       'amount': 100000},]
                      # {
                      #  'input_tx_hash': b'\xcd\x91\xdb]?k\xfb\x01>P{@|\xf39\xd8\x97\xcc<\xce\ro\xed\xfe\xf1\xddFi\xfcNi`',
                      #  # 60694efc6946ddf1feed6f0dce3ccc97d839f37c407b503e01fb6b3f5ddb91cd
                      #  'receiver': 'bchtest:qz4td4hpdpew2d2d6jp58f7n3yapy9wg2c3umcuqn5',
                      #  's': unhexlify("76a9148ed9264f34b3677aba20ba18a50ba4a2fb119dea88ac"),
                      #  'input_out': 0,
                      #  'private_key': b'\x028\xb9\x94\xd8\xc2j@g\xa6K\xfb\xc0\x80m\xe7\xb3\xb5\x9c-k;\x16\x9a16\xb0H\xceH/T',
                      #   #  KwJ2eyPgQJ4vtqffTBZXXF5anqqBJxJXkYZD4DmshhF8LKWnx8AK
                      #  'amount': 40605000
                      # }]
        tx = Transaction(1, [], [], 0)
        for i in input_list:
            tx.add_input(i["input_tx_hash"], i["input_out"], sig_script = i["s"],amount=i["amount"], private_key=i["private_key"])
            print(tx.tx_in)
        tx.add_P2PKH_output(99000, "1E2K64b281k5REC1QF66KRUsC5UqmqZamc")
        # print("out >>", tx.tx_out[0].pk_script.raw)
        # print(address2hash160("bchtest:qz4td4hpdpew2d2d6jp58f7n3yapy9wg2c3umcuqn5"))
        print("beofre sign ", tx.serialize(True))
        for i,_ in enumerate(tx.tx_in):
            tx.sign_P2PKH_input(SIGHASH_ALL, i)
        raw_tx = tx.serialize(hex=True)
        print("raw tx: ",raw_tx)
        # self.assertEqual(raw_tx, signed_tx)

"""
0100000001be514086c903826e846fca2a885bc3f71255659b9cbc0d7298b42670d10b8581000000006b483045022100f116426bb433facd9dc7d7bb5dc91a760acd1932da895c0ea8279f9651fecda8022022dc45435a23236924995167cbee6a6fc79b08c6ce654f6f48128a7433ce0254412103c96acf50ba43e2f603eaf777b35ebb9b80310814f6b8366743282c73599f9e0affffffff0194a33501000000001976a914aab6d6e16872e5354dd48343a7d3893a1215c85688ac00000000
"""