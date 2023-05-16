'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-04-24 16:19:44
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-06 00:02:28
Description  : 
'''
from typing import List, Union, Optional
import struct


class SM4:
    __SBox = [
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
    ]
    __FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
    __CK = [
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    ]

    def __init__(self, IV="F"*32) -> None:
        assert len(IV) == 32
        self.IV = [int(IV[i:i+8], 16) for i in range(0, len(IV), 8)]

    def __pkcs7_padding(self, data: bytes, block=16) -> bytes:
        tmp = block-len(data) % block
        for i in range(tmp):
            data += struct.pack('B', tmp)
        return data

    def __pkcs7_unpadding(self, data: List, block=16) -> bytes:
        num = struct.unpack('B', data[-1])[0]
        for i in range(num):
            data.pop()
        return b"".join(data)

    def __circle_binary_lmove32(self, num: int, n: int) -> int:
        '''
        32位左循环移位   
         
        参数:  
        * num   要移位的数字
        * n     移位位数  
        '''
        assert n != 32 and n >= 0
        left_part = (num << n) & 0xFFFFFFFF
        right_part = (num >> (32 - n)) & 0xFFFFFFFF
        return left_part | right_part

    def __circle_binary_rmove32(self, num: int, n: int) -> int:
        '''
        32位右循环移位

        参数:
        * num   要移位的数字
        * n     移位位数   
        '''
        assert n != 32 and n >= 0
        right_part = (num >> n) & 0xFFFFFFFF
        left_part = (num << (32-n)) & 0xFFFFFFFF
        return left_part | right_part

    def __SBox_change(self, *nums: int):
        '''
        S盒变换

        参数:
        * nums  需要S盒变换的数(0~255)组成的数组
        '''
        res = []
        for num in nums:
            i = num >> 4
            j = num % 16
            res.append(self.__SBox[i*16+j])
        return res

    def __key_T(self, n: int):
        '''
        密钥扩展算法中的轮密钥生成的T

        参数:
        * n 变换的数
        '''
        a0 = n >> 24
        a1 = (n >> 16) % 256
        a2 = (n >> 8) % 256
        a3 = n % 256
        a0, a1, a2, a3 = self.__SBox_change(a0, a1, a2, a3)
        B = (a0 << 24) + (a1 << 16) + (a2 << 8) + a3
        return B ^ (self.__circle_binary_lmove32(B, 13))\
                 ^ (self.__circle_binary_lmove32(B, 23))

    def __round_T(self, n: int):
        '''
        密钥扩展算法中的轮密钥生成的T

        参数:
        * n 变换的数
        '''
        a0 = n >> 24
        a1 = (n >> 16) % 256
        a2 = (n >> 8) % 256
        a3 = n % 256
        a0, a1, a2, a3 = self.__SBox_change(a0, a1, a2, a3)
        B = (a0 << 24) + (a1 << 16) + (a2 << 8) + a3
        return B ^ (self.__circle_binary_lmove32(B, 2)) \
                 ^ (self.__circle_binary_lmove32(B, 10)) \
                 ^ (self.__circle_binary_lmove32(B, 18)) \
                 ^ (self.__circle_binary_lmove32(B, 24))

    def __get_K(self, MK: bytes):
        '''
        获取K

        参数:
        * MK 输入的密钥
        '''
        tmp = []
        for i in range(0, len(MK), 4):
            tmp.append((MK[i] << 24)+(MK[i+1] << 16)+(MK[i+2] << 8)+(MK[i+3]))
        MK0, MK1, MK2, MK3 = tmp
        K0 = MK0 ^ self.__FK[0]
        K1 = MK1 ^ self.__FK[1]
        K2 = MK2 ^ self.__FK[2]
        K3 = MK3 ^ self.__FK[3]
        return [K0, K1, K2, K3]

    def __round_key(self, MK: bytes):
        '''
        轮密钥生成

        参数: 
        * MK 输入的密钥
        '''
        K = self.__get_K(MK)
        rk = []
        for i in range(32):
            K[(i + 4) % 4] = K[i % 4] \
                    ^ self.__key_T(K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ self.__CK[i])
            rk.append(K[(i + 4) % 4])
        return rk

    def __encode(self, msg: Union[str, bytes]):
        '''
        对输入文本进行处理

        参数:
        * msg 输入文本
        '''
        msg = msg.encode() if isinstance(msg, str) else msg
        res = []
        padded_data = self.__pkcs7_padding(msg)
        for i in range(0, len(padded_data), 4):
            res.append((padded_data[i] << 24)
                       +(padded_data[i+1] << 16)
                       +(padded_data[i+2] << 8)
                       +(padded_data[i+3]))
        return res

    def __decode(self, msg: str):
        '''
        对解密后的数据进行解码

        参数:
        * msg 解密后的数据
        '''
        res = []
        for i in range(0, len(msg), 2):
            res.append(struct.pack('<B', int(msg[i:i+2], 16)))
        return self.__pkcs7_unpadding(res)

    def __extend_key(self, key: Union[str, bytes]) -> bytes:
        '''
        填充密钥

        参数:
        * key 输入密钥
        '''
        if isinstance(key, str):
            key = key.encode()
        if len(key) < 16:
            return self.__pkcs7_padding(key)
        else:
            return key[0:16]

    def encrypt(self, msg: Union[str, bytes], MK: Union[str, bytes]) -> bytes:
        '''
        加密

        参数:
        * msg   加密文本
        * MK    密钥
        '''
        MK = self.__extend_key(MK)
        rk = self.__round_key(MK)
        P = self.__encode(msg)
        res = ""
        for i in range(0, len(P), 4):
            X = P[i:i+4]
            for j in range(32):
                X[(j+4) % 4] = X[(j+4) % 4] \
                              ^ (self.__round_T(X[(j+1) % 4] ^ X[(j+2) % 4] ^ X[(j+3) % 4] ^ rk[j]))
            res += "%08X%08X%08X%08X" % (X[3], X[2], X[1], X[0])
        return bytes.fromhex(res)

    def decrypt(self, msg: str, MK: Union[str, bytes]) -> bytes:
        '''
        解密

        参数:
        * msg   要解密的密文
        * MK    密钥
        '''
        MK = self.__extend_key(MK)
        rk = self.__round_key(MK)
        res = ""
        for i in range(0, len(msg), 32):
            c = int(msg[i:i+32], 16)
            X = [c >> 96, (c >> 64) & 0xFFFFFFFF, (c >> 32) & 0xFFFFFFFF, c & 0xFFFFFFFF]
            for j in range(32):
                X[(j+4) % 4] = X[(j+4) % 4] \
                            ^ (self.__round_T(X[(j+1) % 4] ^ X[(j+2) % 4]  ^ X[(j+3) % 4] ^ rk[31-j]))
            res += "%08X%08X%08X%08X" % (X[3], X[2], X[1], X[0])
        return self.__decode(res)

    def encrypt_cbc(self, msg: Union[str, bytes], MK: Union[str, bytes]) -> bytes:
        '''
        CBC模式加密

        参数:
        * msg   加密文本
        * MK    密钥
        '''
        MK = MK if isinstance(MK, bytes) else MK.encode()
        MK = self.__extend_key(MK)
        rk = self.__round_key(MK)
        P = self.__encode(msg)
        res = ""
        pre = self.IV
        for i in range(0, len(P), 4):
            X = [P[i] ^ pre[0], P[i+1] ^ pre[1], P[i+2] ^ pre[2], P[i+3] ^ pre[3]]
            for j in range(32):
                X[(j+4) % 4] = X[(j+4) % 4] \
                    ^ (self.__round_T(X[(j+1) % 4] ^ X[(j+2) % 4] ^ X[(j+3) % 4] ^ rk[j]))
            pre = [X[3], X[2], X[1], X[0]]
            res += "%08X%08X%08X%08X" % (pre[0], pre[1], pre[2], pre[3])
        return bytes.fromhex(res)

    def decrypt_cbc(self, msg: Union[str, bytes], MK: bytes):
        '''
        CBC模式解密

        参数:
        * msg   要解密的密文
        * MK    密钥
        '''
        MK = self.__extend_key(MK)
        rk = self.__round_key(MK)
        res = ""
        msg = msg if isinstance(msg, str) else "0" * (32-len(msg.hex())) + msg.hex()
        msg = "%08X%08X%08X%08X" % (self.IV[0], self.IV[1], self.IV[2], self.IV[3]) + msg
        for i in range(len(msg), 63, -32):
            c = int(msg[i-32:i], 16)
            num = int(msg[i-64:i-32], 16)
            X = [c >> 96, (c >> 64) & 0xFFFFFFFF, (c >> 32) & 0xFFFFFFFF, c & 0xFFFFFFFF]
            last = [num >> 96, (num >> 64) & 0xFFFFFFFF, (num >> 32) & 0xFFFFFFFF, num & 0xFFFFFFFF]
            for j in range(32):
                X[(j+4) % 4] = X[(j+4) % 4] \
                        ^ (self.__round_T(X[(j+1) % 4] ^ X[(j+2) % 4] ^ X[(j+3) % 4] ^ rk[31-j]))
            res = "%08X%08X%08X%08X" % (
                X[3] ^ last[0], X[2] ^ last[1], X[1] ^ last[2], X[0] ^ last[3]) + res
        return self.__decode(res)


if __name__ == '__main__':
    a = SM4()
    print(a.encrypt_cbc("1234", ("1234"*4).encode()))
    from gmssl import sm4
    b = sm4.CryptSM4()
    b.set_key(("1234"*4).encode(),mode=sm4.SM4_ENCRYPT)
    print(b.crypt_cbc(bytes.fromhex("F"*32),b"1234"))

