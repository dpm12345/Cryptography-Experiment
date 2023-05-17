'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-04-27 14:25:45
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-17 17:49:54
Description  : 
'''
import gmpy2
import sha1
import DES
from math import ceil

default_ecc_table = {
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    'q': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
}


class ANSIX917:
    '''
    ANSI X9.17伪随机数产生器
    '''
    def __init__(self, K1: bytes, K2: bytes, V: bytes) -> None:
        self.K1 = K1
        self.K2 = K2
        self.V = V

    def __EDE(self, data):
        '''
        使用两个密钥的三重DES
        '''
        D1 = DES.DES(self.K1)
        D2 = DES.DES(self.K2)
        return D1.encrypt(D2.decrypt(D1.encrypt(data)))

    def generator(self, size=64):
        '''
        生成一个比特长度为size随机数
        '''
        import time
        res = bytes()
        for i in range(0, size, 64):
            t = time.strftime("%Y%m%d%H%M%S", time.localtime())
            DT = bytes.fromhex(t + "%02X" % sum(map(int,t)))
            E = int(self.__EDE(DT).hex(), 16)
            hex1 = "%016x" % (int(self.V.hex(), 16) ^ E)
            R = self.__EDE(bytes.fromhex(hex1))
            hex2 = "%016x" % (int(R.hex(), 16) ^ E)
            V2 = self.__EDE(bytes.fromhex(hex2))
            self.V = V2
            res += R
        return int(res[0:ceil(size/8)].hex(), 16) >> (ceil(size/8)*8 - size)


ansix917 = ANSIX917(b"Test1111", b"Test2222", b"12345678")


def get_random_k(start, end, bit_length=64):
    '''
    返回一个在区间[start,end]的随机数

    参数
    * start 左边界
    * end 右边界
    * bit_length 需要生成的随机数比特位
    '''
    num = ansix917.generator(bit_length) % (end - start + 1) + start
    return num


def remove_whitespace(text):
    """
    移除字符串中所有的空白字符

    Removes all whitespace from passed in string
    """
    import re
    return re.sub(r"\s+", "", text, flags=re.UNICODE)


class EllipticCurve:
    def __init__(self, ecc_table: dict[str, str] = default_ecc_table) -> None:
        self.ecc_table = ecc_table
        for key, val in self.ecc_table.items():
            self.ecc_table[key] = remove_whitespace(val)
        self.len = len(ecc_table['q'])

    def check_is_on_curve(self, P):
        '''
        检查点是否在椭圆曲线上
        '''
        x = int(P[0:self.len], 16)
        y = int(P[self.len:2*self.len], 16)
        a = int(self.ecc_table['a'], 16)
        b = int(self.ecc_table['b'], 16)
        p = int(self.ecc_table['p'], 16)
        left = y * y % p
        right = (x * x * x + a * x + b) % p
        return left == right

    def convert_jacb_to_nor(self, P: str):
        '''
        Jacobian加重射影坐标转换成仿射坐标
        
        参数:
        * P Jacobian加重射影坐标
        '''
        x = int(P[0:self.len], 16)
        y = int(P[self.len:2*self.len], 16)
        z = int(P[2*self.len:], 16)
        p = int(self.ecc_table['p'], base=16)
        z_inv = pow(z, p - 2, p)
        z_invSquar = (z_inv * z_inv) % p
        z_invQube = (z_invSquar * z_inv) % p
        x_new = (x * z_invSquar) % p
        y_new = (y * z_invQube) % p
        z_new = (z * z_inv) % p
        if z_new == 1:
            form = ('%%0%dx' % self.len) * 2
            return form % (x_new, y_new)
        else:
            return None

    def double_point(self, P: str):
        '''
        倍点运算

        参数:
        * P 点
        '''
        P_len = len(P)
        twice_form_len = self.len * 2
        if P_len < twice_form_len:
            return None
        x1 = int(P[0:self.len], 16)
        y1 = int(P[self.len:twice_form_len], 16)
        if P_len > twice_form_len:
            z1 = int(P[twice_form_len:], 16)
        else:
            z1 = 1
        p = int(self.ecc_table['p'], base=16)
        T6 = (z1 * z1) % p
        T2 = (y1 * y1) % p
        T3 = (x1 + T6) % p
        T4 = (x1 - T6) % p
        T1 = (T3 * T4) % p
        T3 = (y1 * z1) % p
        T4 = (T2 * 8) % p
        T5 = (x1 * T4) % p
        T1 = (T1 * 3) % p
        T6 = (T6 * T6) % p
        T6 = ((int(self.ecc_table['a'], 16)+3) * T6) % p
        T1 = (T1 + T6) % p
        z3 = (T3 + T3) % p
        T3 = (T1 * T1) % p
        T2 = (T2 * T4) % p
        x3 = (T3 - T5) % p
        if (T5 % 2) == 1:
            T4 = (T5 + ((T5 + p) >> 1) - T3) % int(self.ecc_table['p'], base=16)
        else:
            T4 = (T5 + (T5 >> 1) - T3) % p
        T1 = (T1 * T4) % p
        y3 = (T1 - T2) % p
        form = ('%%0%dx' % self.len) * 3
        return form % (x3, y3, z3)

    def add_point(self, P1: str, P2: str):
        '''
        点加函数,

        参数
        * P1 Jacobian加重射影坐标 (x,y,z)
        * P2 仿射坐标 (x,y)
        '''
        P1_len = len(P1)
        P2_len = len(P2)
        twice_form_len = self.len * 2
        if P1_len < twice_form_len or P2_len < twice_form_len:
            return None
        X1 = int(P1[0:self.len], 16)
        Y1 = int(P1[self.len:twice_form_len], 16)
        if P1_len > twice_form_len:
            Z1 = int(P1[twice_form_len:], 16)
        else:
            Z1 = 1
        X2 = int(P2[0:self.len], 16)
        Y2 = int(P2[self.len:twice_form_len], 16)
        p = int(self.ecc_table['p'], base=16)
        T1 = (Z1 * Z1) % p
        T2 = (Y2 * Z1) % p
        T3 = (X2 * T1) % p
        T1 = (T1 * T2) % p
        T2 = (T3 - X1) % p
        T3 = (T3 + X1) % p
        T4 = (T2 * T2) % p
        T1 = (T1 - Y1) % p
        Z3 = (Z1 * T2) % p
        T2 = (T2 * T4) % p
        T3 = (T3 * T4) % p
        T5 = (T1 * T1) % p
        T4 = (X1 * T4) % p
        X3 = (T5 - T3) % p
        T2 = (Y1 * T2) % p
        T3 = (T4 - X3) % p
        T1 = (T1 * T3) % p
        Y3 = (T1 - T2) % p
        form = ('%%0%dx' % self.len) * 3
        return form % (X3, Y3, Z3)

    def kP(self, k, P: str):
        '''
        计算点乘 k * P

        参数:
        * k 点乘系数
        * P 椭圆曲线上的点 (x,y)
        '''
        Point = P + "1"
        mask_str = '8'
        for i in range(self.len - 1):
            mask_str += '0'
        mask = int(mask_str, 16)
        Temp = Point
        flag = False
        for n in range(self.len * 4):
            if (flag):
                Temp = self.double_point(Temp)
            if (k & mask) != 0:
                if (flag):
                    Temp = self.add_point(Temp, Point)
                else:
                    flag = True
                    Temp = Point
            k = k << 1
        return self.convert_jacb_to_nor(Temp)
    

    def make_key_pair(self):
        '''
        生成密钥对
        '''
        d = get_random_k(1, int(self.ecc_table['q'], 16)-1, self.len * 4)
        Q = self.kP(d, self.ecc_table['g'])
        return hex(d)[2:], Q


class PublicKey:
    '''
    公钥类
    '''

    def __init__(self, ellipticcurve: EllipticCurve, public_key) -> None:
        self.ellipticcurve = ellipticcurve
        self.public_key = public_key

    
    def set_ellipticcurve(self, ellipticcurve: EllipticCurve):
        '''
        设置椭圆曲线
        '''
        self.ellipticcurve = ellipticcurve

    def set_key(self,key):
        '''
        设置公钥
        '''
        self.public_key = key

    def verify(self, msg, sign: tuple[str, str]):
        '''
        验证签名
        '''
        r, s = map(lambda x: int(x, 16), sign)
        q = int(self.ellipticcurve.ecc_table['q'], 16)
        hash = sha1.SHA1().hash(msg)
        h = int(hash, 16) % q \
            if len(hash) <= self.ellipticcurve.len else int(hash[:self.ellipticcurve.len], 16) % q
        h = h >> max(0, (len(hex(h)) * 4 - len(bin(q)) - 6))
        w = int(gmpy2.invert(s, q))  # type: ignore
        Q = self.public_key
        u1 = w * h % q
        u2 = r * w % q
        point1 = self.ellipticcurve.kP(u1, self.ellipticcurve.ecc_table['g'])
        point2 = self.ellipticcurve.kP(u2, Q)
        if not point1 or not point2:
            return False
        if point1 == point2:
            X = self.ellipticcurve.convert_jacb_to_nor(
                self.ellipticcurve.double_point(point1)
            )
        else:
            X = self.ellipticcurve.convert_jacb_to_nor(
                self.ellipticcurve.add_point(point1, point2)
            )
        if not X:
            return False
        v = int(X[0:self.ellipticcurve.len], 16) % q
        return v == r
    

class PrivateKey:
    '''
    私钥类
    '''

    def __init__(self, ellipticcurve: EllipticCurve, private_key) -> None:
        self.ellipticcurve = ellipticcurve
        self.private_key = private_key


    def set_ellipticcurve(self, ellipticcurve: EllipticCurve):
        '''
        设置椭圆曲线
        '''
        self.ellipticcurve = ellipticcurve
        
    def set_key(self,key):
        '''
        设置私钥
        '''
        self.private_key = key

    def sign(self, msg: bytes):
        '''
        签名
        '''
        r = 0
        s = 0
        while r == 0 or s == 0:
            d = int(self.private_key, 16)
            q = int(self.ellipticcurve.ecc_table['q'], 16)
            k = get_random_k(1, q-1, self.ellipticcurve.len * 4)
            if int(gmpy2.gcd(k, q)) != 1:  # type: ignore
                continue
            Point = self.ellipticcurve.kP(k, self.ellipticcurve.ecc_table['g'])
            if not Point:
                continue
            x1 = int(Point[0:self.ellipticcurve.len], 16)
            r = x1 % q
            k_inv = int(gmpy2.invert(k, q))  # type: ignore
            hash = sha1.SHA1().hash(msg)
            h = int(hash, 16) % q \
                if len(hash) <= self.ellipticcurve.len else int(hash[:self.ellipticcurve.len], 16) % q
            h = h >> max(0, (len(hex(h)) * 4 - len(bin(q)) - 6))
            s = k_inv * (h + d * r) % q

        return (hex(r)[2:], hex(s)[2:])


if __name__ == "__main__":
    for i in range(10000000000):
        print(get_random_k(1,6000))
        # print(ansix917.V)

