'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-04-27 14:30:06
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-05 21:28:13
Description  : 
'''
from typing import Union,List
import struct

class SHA1:
    __H = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
    __K = 0x00000000
    def __init__(self) -> None:
        pass

    def __circle_binary_lmove32(self,num:int,n:int) -> int:
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
    
    def __circle_binary_rmove32(self,num:int,n:int) -> int:
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
    
    def __padding_and_append(self,msg:Union[str,bytes]) -> bytes:
        '''
        填充函数
        '''
        if isinstance(msg,str):
            msg = msg.encode()
        new_msg = [struct.pack("B",item) for item in msg]
        new_msg.append(struct.pack('B',0x80))
        length = len(msg) * 8
        if length % 512 == 448:
            add_length = 504
        else:
            add_length = (448 - length % 512 ) % 512 - 8
        for _ in range(add_length//8):
            new_msg.append(struct.pack('B',0x00))
        new_msg.append(struct.pack('>Q',length & 0xFFFFFFFFFFFFFFFF))
        return b''.join(new_msg)
    

    def __F(self,B,C,D,t:int):
        '''
        逻辑函数
        '''
        if 0 <= t and t <= 19:
            self.__K = 0x5A827999
            return (B & C) | (~B & D)
        elif 20 <= t and t <= 39:
            self.__K = 0x6ED9EBA1
            return B ^ C ^ D
        elif 40 <= t and t <= 59:
            self.__K = 0x8F1BBCDC
            return (B & C) | (B & D) | (C & D)
        elif 60 <= t and t <= 79:
            self.__K = 0xCA62C1D6
            return B ^ C ^ D
    

    def __msg_extend(self,B:int) -> List[int]:
        '''
        消息扩展

        参数:
        * B 消息分组
        '''
        W = []
        for i in range(16):
            W.append((B >> (480 - 32 * i)) & 0xFFFFFFFF)
        for t in range(16, 80):
            W.append(self.__circle_binary_lmove32(W[t-16]^W[t-14]^W[t-8]^W[t-3],1))
        return W
    
    def __CF(self,V,B) -> List[int]:
        '''
        压缩函数
        
        '''
        W = self.__msg_extend(B)
        a, b, c, d, e = V
        for j in range(0, 80):
            a, b, c, d, e = \
                (e+self.__F(b,c,d,j)+self.__circle_binary_lmove32(a,5)+W[j]+self.__K) & 0xFFFFFFFF,\
                a,\
                self.__circle_binary_lmove32(b,30),\
                c,\
                d
        V2 = [a,b,c,d,e]
        return [(V[i]+V2[i])&0xFFFFFFFF for i in range(5)]
    def hash(self,msg:Union[str,bytes]) -> str:
        padded_data = self.__padding_and_append(msg)
        B = [int(padded_data[i:i+64].hex(),16) for i in range(0,len(padded_data),64)]
        V = self.__H
        for item in B:
            V = self.__CF(V,item)
        
        return ''.join(map(lambda x : "%08X" % x,V))

if __name__ == "__main__":
    a = SHA1().hash("1")
    from hashlib import sha1
    print(a)
    print(sha1("1".encode()).hexdigest())
    print(int(a,16))