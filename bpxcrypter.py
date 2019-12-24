#!/usr/bin/env python
#-*- coding: utf-8 -*-

import ctypes
from Crypto.Cipher import AES

try:
    from SocketServer import ThreadingTCPServer, StreamRequestHandler
except:
    from socketserver import ThreadingTCPServer, StreamRequestHandler


IPC_SERVER = ("127.0.0.1", 9999)


class MyXBurpIPCServer(StreamRequestHandler):

    def handle(self):
        data = ""
        while True:
            _sp = self.request.recv(1024)
            if _sp and len(_sp) > 0:
                data += _sp.decode()

                if len(_sp) < 1024:
                    break
            else:
                break

        try:
            if isinstance(data, bytes):
                data = data.decode()

            handled_data = self.xcrypt(str(data))

            if isinstance(handled_data, bytes):
                self.request.sendall(handled_data)
            elif isinstance(handled_data, str):
                self.request.sendall(handled_data.encode())
            else:
                print("error - data type error!")

        except Exception as e:
            print("error - %s" % e)
            self.request.sendall(str(e).encode())

        self.request.close()


    def xcrypt(self, data):
        '''
        overload this function.
        '''
        if data.startswith("\x01"):
            return self.encrypt(data[1:])

        if data.startswith("\x02"):
            return self.decrypt(data[1:])

        if data.startswith("\x03"):
            return self.sign(data[1:])

        else:
            print("error - unknown data!")
            self.request.close()

    @staticmethod
    def pkcs7padding(text):
        """
        明文使用PKCS7填充
        最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
        :param text: 待加密内容(明文)
        :return:
        """
        b_flag = False
        if isinstance(text, bytes):
            b_flag = True
            text = text.decode()

        bs = AES.block_size  # 16
        length = len(text)
        bytes_length = len(bytes(text, encoding='utf-8'))
        # tips：utf-8编码时，英文占1个byte，而中文占3个byte
        padding_size = length if(bytes_length == length) else bytes_length
        padding = bs - padding_size % bs
        # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
        padding_text = chr(padding) * padding
        r = text + padding_text
        return r.encode() if b_flag else r


    @staticmethod
    def pkcs7unpadding(text):
        """
        处理使用PKCS7填充过的数据
        :param text: 解密后的字符串
        :return:
        """
        b_flag = False
        if isinstance(text, bytes):
            b_flag = True
            text = text.decode()

        length = len(text)
        unpadding = ord(text[length-1])
        return text[0:-unpadding].encode() if b_flag else text[0:-unpadding]


    @classmethod
    def run(clazz):
        server = ThreadingTCPServer(IPC_SERVER, clazz)
        server.serve_forever()


    @staticmethod
    def bytes_to_str(bs):
        r = bytearray()
        for i in bs:
            r.append(ctypes.c_uint8(i).value)
        return r.decode("utf-8")

    @staticmethod
    def str_to_bytes(s):
        r = bytearray()
        for i in s:
            r.append(ctypes.c_uint8(i).value)
        return bytes(r)

