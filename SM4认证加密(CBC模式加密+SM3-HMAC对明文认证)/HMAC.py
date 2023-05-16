'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-04-26 08:05:55
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-17 01:57:46
Description  : 
'''
from typing import Callable, Union
import struct


class HMAC:

    def __init__(self, hash: Union[Callable, object], **args) -> None:
        '''
        初始化

        参数:
        * hash 采用的哈希算法

               若输入为类对象,需要表明其哈希函数名称 name

               若输入为函数,若为内置函数,则只需填写这一项,否则需要填写分组大小(比特) blocksize
        * args 其他可能需要的参数
        '''
        self.ipad = 0b00110110
        self.opad = 0b01011100
        if isinstance(hash, Callable):
            self.hash = hash
            try:
                self.blocksize = hash().block_size * 8
            except:
                self.blocksize: int = args.get("blocksize")      # type: ignore
        else:
            self.hash = getattr(hash, args.get("name"))      # type: ignore
            self.blocksize = getattr(hash, "blocksize")  # type: ignore

    def __extend_to_b_size(self, data: bytes) -> bytes:
        '''
        将数据扩充为 b 比特
        '''
        if len(data) * 8 < self.blocksize:
            data = data + struct.pack("B", 0) * \
                (self.blocksize // 8 - len(data))
        elif len(data) * 8 > self.blocksize:
            data = self.__extend_to_b_size(self.__str_to_bytes(self.__use_hash(data)))
        else:
            pass
        return data

    def __str_to_bytes(self, hexstr: str) -> bytes:
        '''
        将十六进制字符串转为字节串
        '''
        from binascii import a2b_hex
        return a2b_hex(hexstr)

    def __use_hash(self, msg: bytes) -> str:
        '''
        使用哈希函数
        '''
        try:
            return self.hash(msg).hexdigest()
        except:
            return self.hash(msg)

    def run(self, msg: Union[bytes, str], K: bytes) -> str:
        '''
        HMAC计算
        '''
        if isinstance(msg, str):
            msg = msg.encode()
        K = self.__extend_to_b_size(K)
        tmp1 = []
        tmp2 = []
        for i in range(len(K)):
            tmp1.append(struct.pack('B', K[i] ^ self.ipad))
            tmp2.append(struct.pack('B', K[i] ^ self.opad))
        H1 = self.__use_hash(b''.join(tmp1) + msg)
        H2 = self.__use_hash(b''.join(tmp2) + self.__str_to_bytes(H1))
        return H2


if __name__ == '__main__':
    import hashlib
    import hmac
    import SM3
    with open('./test.txt', "r", encoding='utf-8') as f:
        plain_text = f.read()
    print(hmac.HMAC(("1"*64).encode(), "1234".encode(), "sm3").hexdigest())
    print(HMAC(SM3.SM3(), name="hash").run("1234".encode(), ("1"*64).encode()))
    print(hmac.HMAC("1234fawfgawgawgawgaw".encode(),"1234".encode(), "md5").hexdigest())
    print(HMAC(hashlib.md5).run("1234".encode(), "1234fawfgawgawgawgaw".encode()))
    print(hmac.HMAC("1234fawfgawgawgawgaw".encode(), "1234".encode(), "sm3").hexdigest())
    print(HMAC(SM3.SM3(), name="hash").run("1234".encode(), "1234fawfgawgawgawgaw".encode()))
    print(HMAC(SM3.SM3().hash, blocksize=512).run("1234".encode(), "1234fawfgawgawgawgaw".encode()))
    print(HMAC(SM3.SM3().hash, blocksize=512).run("1234", "1234fawfgawgawgawgaw".encode()))
