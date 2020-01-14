#!/usr/bin/env python
#-*- coding: utf-8 -*-

import pdb
import ctypes
import binascii
from Crypto.Cipher import AES

try:
    from SocketServer import ThreadingTCPServer, StreamRequestHandler
except:
    from socketserver import ThreadingTCPServer, StreamRequestHandler


IPC_SERVER = ("127.0.0.1", 9999)




def bytes_to_str(bs):
    r = ""
    for i in bs:
        r += chr(ctypes.c_uint8(i).value)
    return r

def str_to_bytes(s):
    r = bytearray()
    for i in s:
        r.append(ctypes.c_uint8(ord(i)).value)
    return bytes(r)


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



class MyTcpServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, server_address, RequestHandlerClass):
        """Set up an initially empty mapping between a user' s nickname
        and the file-like object used to send data to that user."""
        ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)


class MyXBurpIPCServer(StreamRequestHandler):
    '''
    如果使用的非对称算法，解密部分建议重载
    decrypt_req:  解密请求数据包的payload
    decrypt_res:  解密返回响应包的payload
    '''

    def handle(self):
        data = b""
        while True:
            _sp = self.request.recv(1024)
            if _sp and len(_sp) > 0:
                data += _sp

                if len(_sp) < 1024:
                    break
            else:
                break

        try:
            # pdb.set_trace()
            if isinstance(data, bytes):
                # 保证递交处理的一定是str类型
                data = bytes_to_str(data)

            handled_data = self.xcrypt(str(data))

            if isinstance(handled_data, bytes):
                self.request.sendall(handled_data)
            elif isinstance(handled_data, str):
                self.request.sendall(str_to_bytes(handled_data))
            else:
                print("error - data type error!")

        except Exception as e:
            print("error - %s" % e)
            self.request.sendall(str(e).encode())

        self.request.close()


    def xcrypt(self, data):

        if data.startswith("\x00"):
            return self._decrypt(data[1:], is_req=None)

        if data.startswith("\x01"):
            return self.encrypt(data[1:])

        if data.startswith("\x02"):
            return self._decrypt(data[1:], is_req=True)

        if data.startswith("\x03"):
            return self._decrypt(data[1:], is_req=False)

        if data.startswith("\x04"):
            return self.sign(data[1:])

        else:
            print("error - unknown data!")
            self.request.close()


    def _decrypt(self, data, is_req=None):
        '''
        针对非对称算法，使用不同的函数去解密。
        '''
        if is_req and hasattr(self, "decrypt_req"):
            return self.decrypt_req(data)

        if is_req is False and hasattr(self, "decrypt_res"):
            return self.decrypt_res(data)

        else:
            try:
                return self.decrypt_res(data)
            except Exception as e:
                print("decrypt_res error - %s" % e)
                try:
                    return self.decrypt_req(data)
                except Exception as ee:
                    print("decrypt_req error - %s" % ee)

            return self.decrypt(data)


    @classmethod
    def run(clazz):
        server = MyTcpServer(IPC_SERVER, clazz)
        server.serve_forever()

