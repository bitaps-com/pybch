import unittest
from pybch import blockchain
from binascii import unhexlify
from pybch import address2hash160


class ScriptDeserializeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting Script class deserialization:\n")
    def test_p2pkh(self):
        print("Deserialize P2PKH")
        s = blockchain.Script("76a9143520dd524f6ca66f63182bb23efff6cc8ee3ee6388ac")
        self.assertEqual(s.type, "P2PKH")
        self.assertEqual(s.ntype, 0)
        self.assertEqual(s.asm, "OP_DUP OP_HASH160 3520dd524f6ca66f63182bb23efff6cc8ee3ee63 OP_EQUALVERIFY OP_CHECKSIG")
        self.assertEqual(s.address[0], address2hash160("15qvBdqSWQCuLQPXVoWViG2GvjeARmpYPw"))
        self.assertEqual(s.pattern, "OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG")
        self.assertEqual(s.op_sig_count, 1)

    def test_p2sh(self):
        print("Deserialize P2SH")
        s = blockchain.Script("a91469f37572ab1b69f304f987b119e2450e0b71bf5c87")
        self.assertEqual(s.type, "P2SH")
        self.assertEqual(s.ntype, 1)
        self.assertEqual(s.asm, "OP_HASH160 69f37572ab1b69f304f987b119e2450e0b71bf5c OP_EQUAL")
        self.assertEqual(s.address[0], address2hash160("3BMEXVsYyfKB5h3m53XRSFHkqi1zPwsvcK"))
        self.assertEqual(s.pattern, "OP_HASH160 <20> OP_EQUAL")
        self.assertEqual(s.op_sig_count, 0)

    def test_null_data(self):
        print("Deserialize NULL_DATA")
        # 20  bytes valid
        s = blockchain.Script("6a144279b52d6ee8393a9a755e8c6f633b5dd034bd67")
        self.assertEqual(s.type, "NULL_DATA")
        self.assertEqual(s.ntype, 3)
        self.assertEqual(s.asm, "OP_RETURN 4279b52d6ee8393a9a755e8c6f633b5dd034bd67")
        self.assertEqual(len(s.address), 0)
        self.assertEqual(s.pattern, "OP_RETURN <20>")
        self.assertEqual(s.op_sig_count, 0)
        # 81 bytes invalid
        s = blockchain.Script("6a4c51000000000000000000000000000000000000000000000000000000000000"
                              "000000000000000000000000000000000000000000000000000000000000"
                              "000000000000000000000000000000000000000000")
        self.assertEqual(s.asm, "OP_RETURN 000000000000000000000000000000000000000000000000000"
                                "0000000000000000000000000000000000000000000000000000000000000"
                                "00000000000000000000000000000000000000000000000000")
        self.assertEqual(s.pattern, "OP_RETURN <81>")
        self.assertEqual(len(s.address), 0)
        self.assertEqual(s.op_sig_count, 0)
        self.assertEqual(s.type, "NON_STANDARD")
        self.assertEqual(s.ntype, 7)

    def test_multisig(self):
        print("Deserialize MULTISIG")
        # 15 from 15
        s = blockchain.Script("5f210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
                              "715fae")
        self.assertEqual(s.pattern, "OP_15 <33> <33> <33> <33> <33> <33> <33> <33> <33> <33> <33> <33> "
                                    "<33> <33> <33> OP_15 OP_CHECKMULTISIG")
        self.assertEqual(s.type, "MULTISIG")
        self.assertEqual(s.ntype, 4)
        self.assertEqual(s.asm, "OP_15 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab"
                                "35c71 OP_15 OP_CHECKMULTISIG")
        self.assertEqual(len(s.address), 15)
        self.assertEqual(s.op_sig_count, 15)

        # 1 from 3
        s = blockchain.Script("512102953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213623"
                              "441048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd795bbf"
                              "410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b042060"
                              "466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcdffb6a97"
                              "40de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e3953ae")
        self.assertEqual(s.pattern, "OP_1 <33> <65> <66> OP_3 OP_CHECKMULTISIG")
        self.assertEqual(s.type, "MULTISIG")
        self.assertEqual(s.ntype, 4)
        self.assertEqual(s.asm, "OP_1 02953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213"
                                "6234 048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd79"
                                "5bbf410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b"
                                "0 060466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcd"
                                "ffb6a9740de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e39"
                                " OP_3 OP_CHECKMULTISIG")
        self.assertEqual(len(s.address), 3)
        self.assertEqual(s.op_sig_count, 3)
