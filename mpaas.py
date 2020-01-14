#!/usr/bin/env python

import pdb
import time
import hashlib
import binascii
from collections import deque

import frida
import IPython

PACKAGE_NAME = 'Gadget'
DEVICE = frida.get_usb_device()
SESSION = None


JS_HOOK_CODE = '''
Java.perform(function (){
    var hook2 = Java.use("com.cgb.mobilebank.sit.launcher.common.ApplicationBase$6$1");
    hook2.onClick.overload("android.content.DialogInterface", "int").implementation = function(arg0, arg1){
        arg0.dismiss();
    };
})
'''

JS_ENC_CODE = '''
Java.perform(function (){

    var hexChar = ["0", "1", "2", "3", "4", "5", "6", "7","8", "9", "A", "B", "C", "D", "E", "F"];

    function javaByteArrayToByteArray(arr) {
        var view = new DataView(new ArrayBuffer(arr.length));

        // send("[*] JavaBytes2BA : Length -> " + arr.length);
        for(var i = 0; i < arr.length; i++) {
            view.setUint8(i, arr[i]);
        }

        return view.buffer;
    }

    function byteArrayToHex(arr) {
        if(typeof arr === 'string') {
            return arr;
        }
        var str = '', _arr = arr;
        var byte;
        for(var i = 0; i < _arr.length; i++) {
            byte = _arr[i];
            str += hexChar[(byte >> 4) & 0x0f] + hexChar[byte & 0x0f];
        }
        return str;
    }

    var hook_class = Java.use("com.alipay.mobile.common.transport.http.selfencrypt.ClientRpcPack");

    hook_class.encrypt.implementation = function(arg0){
        var mr1 = this.encrypt(arg0);
        send(byteArrayToHex(arg0) + "|||" + byteArrayToHex(mr1));
        return mr1;
    };

});
'''


JS_DEC_CODE = '''
Java.perform(function (){

    var hexChar = ["0", "1", "2", "3", "4", "5", "6", "7","8", "9", "A", "B", "C", "D", "E", "F"];

    function javaByteArrayToByteArray(arr) {
        var view = new DataView(new ArrayBuffer(arr.length));

        // send("[*] JavaBytes2BA : Length -> " + arr.length);
        for(var i = 0; i < arr.length; i++) {
            view.setUint8(i, arr[i]);
        }

        return view.buffer;
    }

    function byteArrayToHex(arr) {
        if(typeof arr === 'string') {
            return arr;
        }
        var str = '', _arr = arr;
        var byte;
        for(var i = 0; i < _arr.length; i++) {
            byte = _arr[i];
            str += hexChar[(byte >> 4) & 0x0f] + hexChar[byte & 0x0f];
        }
        return str;
    }

    var hook_class = Java.use("com.alipay.mobile.common.transport.http.selfencrypt.ClientRpcPack");

    hook_class.decrypt.implementation = function(arg0){
        var mr2 = this.decrypt(arg0);
        send(byteArrayToHex(arg0) + "|||" + byteArrayToHex(mr2));
        return mr2;
    };

});
'''

from bpxcrypter import *


class FridaBridge(object):

    enc_queue = deque(maxlen=50)
    dec_queue = deque(maxlen=50)

    def __init__(self):
        script = SESSION.create_script(JS_HOOK_CODE)
        script.on('message', None)
        script.load()

    def load_encrypt_script(self):
        script = SESSION.create_script(JS_ENC_CODE)
        script.on('message', self.get_enc_messages_from_js)
        script.load()

    def load_decrypt_script(self):
        script = SESSION.create_script(JS_DEC_CODE)
        script.on('message', self.get_dec_messages_from_js)
        script.load()

    def get_enc_messages_from_js(self, message, data):
        if "payload" in message:
            payload = message["payload"]
            # print("[+] Get Enc -> %s" % payload)
            plain, cipher = payload.split("|||")
            FridaBridge.enc_queue.append({
                "plain": binascii.unhexlify(plain),
                "cipher": cipher[-16:].lower(),
            })

        else:
            if message["type"] == 'error':
                print(message['stack'])
            else:
                print(message)

    def get_dec_messages_from_js(self, message, data):
        if "payload" in message:
            payload = message["payload"]
            # print("[+] Get Dec -> %s" % payload)
            cipher, plain = payload.split("|||")
            FridaBridge.dec_queue.append({
                "plain": binascii.unhexlify(plain),
                "cipher": cipher[-16:].lower(),
            })

        else:
            if message["type"] == 'error':
                print(message['stack'])
            else:
                print(message)


class GFBankHelper(MyXBurpIPCServer):

    def encrypt(self, data):
        pass

    def decrypt_res(self, data):
        _m = binascii.hexlify(str_to_bytes(data))
        _i = bytes_to_str(_m)[-16:].lower()
        for m in list(FridaBridge.dec_queue)[::-1]:
            if m.get("cipher") == _i:
                return m.get("plain")

        raise Exception("Not found!")

    def decrypt_req(self, data):
        _m = binascii.hexlify(str_to_bytes(data))
        _i = bytes_to_str(_m)[-16:].lower()
        for m in list(FridaBridge.enc_queue)[::-1]:
            if m.get("cipher") == _i:
                return m.get("plain")

        raise Exception("Not found!")

    def sign(self, data):
        pass


if __name__ == '__main__':
    # PID = DEVICE.spawn([PACKAGE_NAME])
    # SESSION = DEVICE.attach(PID)
    SESSION = DEVICE.attach(PACKAGE_NAME)
    time.sleep(2)
    fb = FridaBridge()
    fb.load_encrypt_script()
    fb.load_decrypt_script()
    DEVICE.resume(PACKAGE_NAME)
    GFBankHelper.run()
    #IPython.embed()

