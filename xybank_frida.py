#!/usr/bin/env python

import pdb
import frida
import ctypes
import base64
import IPython

PACKAGE_NAME = 'Gadget'
DEVICE = frida.get_usb_device()
SESSION = None


KEY = '8f4f6bae4cbb4890'

JS_ENC_CODE = '''
Java.perform(function (){
    var hook_class = Java.use('com.cib.sm.comunication.CryptoUtil');
    var jstring = Java.use('java.lang.String');

    var msg = jstring.$new('%s');
    var key = jstring.$new('%s');

    var cipher = hook_class.encryptByAES(msg.getBytes("utf-8"), key);
    send(cipher);
});
'''

JS_DEC_CODE = '''
Java.perform(function (){
    var hook_class = Java.use("com.cib.sm.comunication.CryptoUtil");
    var jstring = Java.use('java.lang.String');

    var msg = Java.array('byte', %s);
    var key = jstring.$new('%s');

    var plain = hook_class.decryptByAES(msg, key);
    send(plain);
});
'''

from bpxcrypter import MyXBurpIPCServer


class FridaBridge(object):

    def __init__(self):
        self._result = None

    def encrypt(self, data):
        self._result = None
        # plain = data.encode() if isinstance(data, bytes) else data
        script = SESSION.create_script(JS_ENC_CODE % (data, KEY))
        script.on('message', self.get_messages_from_js)
        script.load()
        while self._result is None:
            pass
        script.unload()
        # pdb.set_trace()
        return base64.b64encode(MyXBurpIPCServer.str_to_bytes(self._result))

    def decrypt(self, data):
        self._result = None
        # cipher = data.encode() if isinstance(data, bytes) else data
        data = base64.b64decode(data)
        cipher = [ctypes.c_int8(i).value for i in data]
        script = SESSION.create_script(JS_DEC_CODE % (str(cipher), KEY))

        script.on('message', self.get_messages_from_js)
        script.load()
        while self._result is None:
            pass
        script.unload()
        # pdb.set_trace()
        return MyXBurpIPCServer.bytes_to_str(self._result)


    def get_messages_from_js(self, message, data):
        if "payload" in message:
            payload = message["payload"]
            # print("[+] Result -> %s" % payload)
            self._result = payload

        else:
            if message["type"] == 'error':
                print(message['stack'])
            else:
                print(message)
            self._result = str(message)


class XYBankFrida(MyXBurpIPCServer):

    def encrypt(self, data):
        fb = FridaBridge()
        return fb.encrypt(data)

    def decrypt(self, data):
        fb = FridaBridge()
        return fb.decrypt(data)

    def sign(self, data):
        return "aabbccddee"


if __name__ == '__main__':
    # PID = DEVICE.spawn([PACKAGE_NAME])
    # SESSION = DEVICE.attach(PID)
    SESSION = DEVICE.attach(PACKAGE_NAME)
    DEVICE.resume(PACKAGE_NAME)
    XYBankFrida.run()
    # fb = FridaBridge()
    # IPython.embed()
