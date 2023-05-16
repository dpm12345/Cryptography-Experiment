
'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-05-04 13:20:21
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-06 15:46:47
Description  : 
'''

import struct
from typing import Union

def int_to_binary(data,size):
    res = ""
    for i in range(size):
        res = str(data & 1) + res
        data = data >> 1 
    assert data == 0
    return res
class DES:
    IV = "F"*32

    # Permutation and translation tables for DES
    __PC1 = [
         56, 48, 40, 32, 24, 16,  8,
          0, 57, 49, 41, 33, 25, 17,
          9,  1, 58, 50, 42, 34, 26,
         18, 10,  2, 59, 51, 43, 35,
         62, 54, 46, 38, 30, 22, 14,
          6, 61, 53, 45, 37, 29, 21,
         13,  5, 60, 52, 44, 36, 28,
         20, 12,  4, 27, 19, 11,  3
    ]

    # number left rotations of pc1
    __left_rotations = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    # permuted choice key (table 2)
    __PC2 = [
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    # initial permutation IP
    __IP = [
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]

    # Expansion table for turning 32 bit blocks into 48 bits
    __expansion_table = [
        31,  0,  1,  2,  3,  4,
         3,  4,  5,  6,  7,  8,
         7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    ]

    # The (in)famous S-boxes
    __SBox = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]


    # 32-bit permutation function P used on the output of the S-boxes
    __P = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23,13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]

    # final permutation IP^-1
    __fp = [
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
        32,  0, 40,  8, 48, 16, 56, 24
    ]
    
    def __init__(self,key:bytes,MODE=None,**args) -> None:
        self.key = key
        self.__round_key = [0] * 16
        self.__round_key_generate()
        self.MODE = MODE
    

    def __pkcs7_padding(self,data:bytes,blocksize=16) -> bytes:
        tmp = blocksize - len(data) % blocksize
        for i in range(tmp):
            data += struct.pack('B',tmp)
        return data
    
    def __pkcs7_unpadding(self,data:bytes,block=16) -> bytes:
        data = bytearray(data)
        num  = data[-1]
        return bytes(data[0:len(data)-num])

    def __round_key_generate(self) -> None:
        '''
        轮密钥生成
        '''
        key_bit = int_to_binary(int(self.key.hex(),16),64)
        key_bit = self.__exchange(self.__PC1,key_bit)
        C = key_bit[0:28]
        D = key_bit[28:]
        for i in range(16):
            C = C[self.__left_rotations[i]:] + C[0:self.__left_rotations[i]]
            D = D[self.__left_rotations[i]:] + D[0:self.__left_rotations[i]]
            self.__round_key[i] = int(self.__exchange(self.__PC2,C+D),2)

    def __s_box_change(self,data:str) -> str:
        '''
        S盒代换
        '''
        res = ""
        for i in range(0,48,6):
            row = int(data[i:i+6][0]+data[i:i+6][-1],2)
            col = int(data[i:i+6][1:5],2)
            res += int_to_binary(self.__SBox[i//6][row*16+col],4)
        return res
    
    def __exchange(self,table,data) -> str:
        '''
        置换函数
        '''
        res = ""
        for num in table:
            res+=data[num]
        return res

    def __F(self,R:str,K:int) -> str:
        extended_data = self.__exchange(self.__expansion_table,R)
        xor_result = int(extended_data,2)^K
        s_box_change_result = self.__s_box_change(int_to_binary(xor_result,48))
        exchange_result = self.__exchange(self.__P,s_box_change_result)
        return exchange_result 
    def set_mode(self,mode):
        self.MODE = mode

    def encrypt(self,data:Union[str,bytes]) -> bytes:
        res = bytes()
        if isinstance(data,str):
            data = data.encode()
        data = self.__pkcs7_padding(data,8) if self.MODE else data
        for i in range(0,len(data),8):
            part = int_to_binary(int(data[i:i+8].hex(),16),64)
            part = self.__exchange(self.__IP,part)
            L = part[0:32]
            R = part[32:64]
            for j in range(16):
                new_L = R
                xor_result = int(L,2) ^ int(self.__F(R,self.__round_key[j]),2)
                new_R = int_to_binary(xor_result,32)
                L = new_L
                R = new_R
            tmp_res = self.__exchange(self.__fp,R+L)

            res += struct.pack(">Q",int(tmp_res,2))
        return res

    def decrypt(self,data:bytes):
        res = bytes()
        if isinstance(data,str):
            data = data.encode()
        for i in range(0,len(data),8):
            part = int_to_binary(int(data[i:i+8].hex(),16),64)
            part = self.__exchange(self.__IP,part)
            L = part[0:32]
            R = part[32:64]
            for j in range(16):
                new_L = R
                xor_result = int(L,2) ^ int(self.__F(R,self.__round_key[15-j]),2)
                new_R = int_to_binary(xor_result,32)
                L = new_L
                R = new_R
            tmp_res = self.__exchange(self.__fp,R+L)

            res += struct.pack(">Q",int(tmp_res,2))
        res = self.__pkcs7_unpadding(res,8) if self.MODE else res
        return res
    

if __name__ == "__main__":
    key = b'12345678'
    data = '1566fwaw'.encode()
    des = DES(key)
    b = DES(b"11111111")
    a = (des.encrypt(data))
    from Crypto.Cipher import DES as f
    print(f.new(key,f.MODE_ECB).encrypt(data) == a)
    print(des.decrypt(a))
    print(f.new(key,f.MODE_ECB).decrypt(a))