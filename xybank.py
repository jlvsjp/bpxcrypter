#!/usr/bin/env python

import pdb
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from bpxcrypter import MyXBurpIPCServer


KEY = b"8f4f6bae4cbb4890"


class XYBankHelper(MyXBurpIPCServer):

    def encrypt(self, data):
        # pdb.set_trace()
        aes = AES.new(KEY, AES.MODE_CBC, iv=KEY)
        r = aes.encrypt(MyXBurpIPCServer.pkcs7padding(data.encode()))
        return b64encode(r)

    def decrypt(self, data):
        # pdb.set_trace()
        cipher = b64decode(data.encode())
        aes = AES.new(KEY, AES.MODE_CBC, iv=KEY)
        r = MyXBurpIPCServer.pkcs7unpadding(aes.decrypt(cipher))
        return r

    def sign(self, data):
        return "aabbccddee"


XYBankHelper.run()
