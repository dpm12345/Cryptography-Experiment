'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-04-26 08:05:55
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-05 21:22:12
Description  : 
'''
from typing import Union,List,Tuple
import struct

class SM3:
    blocksize = 512
    __IV = [0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E]
    __T = [
        0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
        0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
        0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
        0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
        0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
        0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
        0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
        0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
        ]
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

    def __FF(self,X,Y,Z,index:int):
        if 0 <= index and index <= 15:
            return X ^ Y ^ Z
        elif 16 <= index  and index <= 63:
            return (X & Y) | (X & Z) | (Y & Z)
        else:
            raise OverflowError
        
    def __GG(self,X,Y,Z,index:int):
        if 0 <= index and index <= 15:
            return X^Y^Z
        elif 16 <= index  and index <= 63:
            return (X & Y) | (~X & Z)
        else:
            raise OverflowError
        
    def __P0(self,X) -> int:
        '''
        置换函数2
        '''
        return X ^ self.__circle_binary_lmove32(X,9) ^ self.__circle_binary_lmove32(X,17)
    
    def __P1(self,X) -> int:
        '''
        置换函数1
        '''
        return X ^ self.__circle_binary_lmove32(X,15) ^ self.__circle_binary_lmove32(X,23)
    
    def __msg_extend(self,B:int) -> Tuple[List[int],List[int]]:
        '''
        消息扩展

        参数:
        * B 消息分组
        '''
        W1 = []
        for i in range(16):
            W1.append((B >> (480 - 32 * i)) & 0xFFFFFFFF)
        for j in range(16, 68):
            W1.append(self.__P1(W1[j-16] ^ W1[j-9] ^ (self.__circle_binary_lmove32(W1[j-3], 15 % 32)))\
                    ^ (self.__circle_binary_lmove32(W1[j-13], 7 % 32)) \
                    ^ W1[j-6]
                    )
        W2 = []
        for j in range(64):
            W2.append(W1[j] ^ W1[j+4])
        
        return W1, W2
    
    def __CF(self,V,B) -> List[int]:
        W1, W2 = self.__msg_extend(B)
        a, b, c, d, e, f, g, h = V
        for j in range(0, 64):
            SS1 = self.__circle_binary_lmove32\
            (
                ((self.__circle_binary_lmove32(a, 12)) + e +
                 (self.__circle_binary_lmove32(self.__T[j], j % 32))
                ) & 0xFFFFFFFF
            , 7
            )
            SS2 = SS1 ^ (self.__circle_binary_lmove32(a, 12))
            TT1 = (self.__FF(a, b, c, j) + d + SS2 + W2[j]) & 0xFFFFFFFF
            TT2 = (self.__GG(e, f, g, j) + h + SS1 + W1[j]) & 0xFFFFFFFF
            d = c
            c = self.__circle_binary_lmove32(b, 9)
            b = a
            a = TT1
            h = g
            g = self.__circle_binary_lmove32(f, 19)
            f = e
            e = self.__P0(TT2)

            a, b, c, d, e, f, g, h = map(lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])

        V2 = [a, b, c, d, e, f, g, h]
        return [V2[i] ^ V[i] for i in range(8)]
    
    def hash(self,msg:Union[str,bytes]):
        padded_data = self.__padding_and_append(msg)
        B = [int(padded_data[i:i+64].hex(),16) for i in range(0,len(padded_data),64)]
        V = self.__IV
        for item in B:
            V = self.__CF(V,item)
        return ''.join(map(lambda x : "%08X" % x,V))
    
if __name__ == '__main__':
    sm3 = SM3()
    print("1"*64)
    from gmssl import sm3 as d
    print(d.sm3_hash(bytearray(b"12")))
    print(sm3.hash("12"))
    