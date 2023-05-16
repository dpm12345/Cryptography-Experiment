'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-05-06 14:28:16
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-06 18:06:40
Description  : 
'''

from DH_ecdsa import *
import re

def print_on_line(edge: str, title: str, data: str, max_len: int) -> None:
    '''
    按照指定格式输出若干行数据
    '''
    chinese_word = re.findall(r"[^\x00-\xff]", title)
    pre_len = len(chinese_word) + len(title)
    data_len = len(data)
    end = max_len - pre_len if max_len - pre_len < data_len else data_len
    print(
        f"{edge} {title}{data[0:end]}{' '* (max_len - pre_len - end)} {edge}")
    for i in range(max_len - pre_len, data_len, max_len):
        end = i + max_len if i + max_len <= data_len else data_len
        print(f"{edge} {data[i:end]}{' ' * (max_len-end+i)} {edge}")


def print_key_sign(name: str, private_key: str, public_key: str, sign: str) -> None:
    '''
    打印密钥和签名

    参数:
    * name 密钥所属者
    * private_key 私钥
    * public_key 公钥
    * sign 签名
    '''
    print(f"| {name}:{' '*(99-len(name))} |")
    sign = "(" + ", ".join(sign) + ")"

    print_on_line("|", "[私钥 private_key] = ", private_key, 100)
    print_on_line("|", "[公钥 public_key] = ", public_key, 100)
    print_on_line("|", "[签名 sign(r,s)] = ", sign, 100)
    print(f"| {' '*100} |")


def check_print(ellipticcurve, name, key1, key2, sign1, sign2) -> None:
    print("-"*104)
    title = f" 使用曲线:{name} "
    length = 11 + len(name)
    left = (100 - length) // 2
    right = 100 - length - left
    print(f'| {"*"*left}{title}{"*"*right} |')
    print_key_sign("Alice", key1[0], key1[1], sign1)
    print_key_sign("Bob", key2[0], key2[1], sign2)

    assert ellipticcurve.check_is_on_curve(key1[1])
    verify_Bob = PublicKey(ellipticcurve, key1[1]).verify(
        "".join(key1[1]), sign1)
    assert verify_Bob
    print_on_line("|", "Bob验证签名结果: True", "", 100)

    assert ellipticcurve.check_is_on_curve(key2[1])
    verify_Alice = PublicKey(ellipticcurve, key2[1]).verify(
        "".join(key2[1]), sign2)
    assert verify_Alice
    print_on_line("|", "Alice验证签名结果: True", "", 100)

    share_key1 = ellipticcurve.kP(int(key1[0], 16), key2[1])
    share_key2 = ellipticcurve.kP(int(key2[0], 16), key1[1])
    assert share_key1
    assert share_key2
    print_on_line("|", "双方计算的共享密钥是否相同: ", str(share_key1 == share_key2), 100)
    assert share_key1 == share_key2
    print_on_line("|", "Alice和Bob的共享密钥: ", share_key1, 100)
    print("-"*104)


def check_print2(ellipticcurve, 
                 name, 
                 msg, 
                 public_key1, 
                 sign1, 
                 Verify, 
                 public_key2, 
                 sign2,
                 sign2_str) -> None:
    print("-"*104)
    title = f" 使用曲线:{name} "
    length = 11 + len(str(name))
    left = (100 - length) // 2
    right = 100 - length - left
    print(f'| {"*"*left}{title}{"*"*right} |')
    print_on_line("|", "[公钥 public_key] = ", public_key1, 100)
    print_on_line("|", "[库签名 sign] = ", f"({', '.join(sign1)})", 100)
    verify_result1 = PublicKey(ellipticcurve, public_key1).verify(msg, sign1)
    print_on_line("|", "自己实现的验证签名结果: ", str(verify_result1), 100)
    print_on_line("|","","",100)

    print_on_line("|", "[公钥 public_key] = ", public_key2, 100)
    print_on_line("|", "[自己实现的签名 sign] = ", f"({', '.join(sign2_str)})", 100)
    verify_result = Verify.verify(sign2,msg)
    print_on_line("|", "库验证签名结果: ", str(verify_result), 100)
    print("-"*104)


def check_my_implementations():
    import curves
    for name, val in curves.__dict__.items():
        # if not name.startswith("__") and val['g'] != "" and name != "Curve22103":
        if not name.startswith("__") and val['g'] != "":
            ellipticcurve = EllipticCurve(val)
            Alice_key = ellipticcurve.make_key_pair()
            Bob_key = ellipticcurve.make_key_pair()

            sign_Alice = PrivateKey(ellipticcurve, Alice_key[0]).sign(
                "".join(Alice_key[1]))
            sign_Bob = PrivateKey(ellipticcurve, Bob_key[0]).sign(
                "".join(Bob_key[1]))

            check_print(ellipticcurve, name, Alice_key, Bob_key, sign_Alice, sign_Bob)

            import os
            os.system('pause')


def check_my_and_std_rep():
    import ecdsa
    from ecdsa.ellipticcurve import Point
    from ecdsa.util import sigdecode_string,sigencode_string
    import curves
    import os
    curve_list = [
        ecdsa.NIST192p, curves.P_192,
        ecdsa.NIST224p, curves.P_224,
        ecdsa.NIST256p, curves.P_256,
        ecdsa.NIST384p, curves.P_384,
        ecdsa.NIST521p, curves.P_521,
        ecdsa.SECP256k1, curves.secp256k1,
        ecdsa.BRAINPOOLP160r1, curves.brainpoolP160r1,
        ecdsa.BRAINPOOLP192r1, curves.brainpoolP192r1,
        ecdsa.BRAINPOOLP224r1, curves.brainpoolP224r1,
        ecdsa.BRAINPOOLP256r1, curves.brainpoolP256r1,
        ecdsa.BRAINPOOLP320r1, curves.brainpoolP320r1,
        ecdsa.BRAINPOOLP384r1, curves.brainpoolP384r1,
        ecdsa.BRAINPOOLP512r1, curves.brainpoolP512r1,
        ecdsa.SECP112r1, curves.secp112r1,
        ecdsa.SECP112r2, curves.secp112r2,
        ecdsa.SECP128r1, curves.secp128r1,
        ecdsa.SECP160r1, curves.secp160r1
    ]
    for i in range(0, len(curve_list), 2):
        msg = b"This is a sample"

        #库生成签名，自己验证
        sk = ecdsa.SigningKey.generate(curve=curve_list[i])
        vk = sk.verifying_key
        signature = sk.sign(msg)
        sign = sigdecode_string(signature, vk.pubkey.order)
        e = EllipticCurve(curve_list[i+1])
        public_key1 = f"%0{e.len}X" % vk.pubkey.point.x(
        ) + f"%0{e.len}X" % vk.pubkey.point.y()
        sign_str1 = tuple(map(lambda x: f"%0{e.len}X" % x, sign))

        assert vk.verify(signature, msg)

        # 自己生成签名，库验证
        d, Q = e.make_key_pair()
        my_priv = PrivateKey(e,d)
        r,s = my_priv.sign(msg)
        sign2 = sigencode_string(int(r,16),int(s,16),curve_list[i].order)
        size = len(Q) // 2
        x = int(Q[0:size],16)
        y = int(Q[size:],16)
        point = Point(curve_list[i].curve,x,y,curve_list[i].order)
        Verify = ecdsa.VerifyingKey.from_public_point(point,curve_list[i])

        check_print2(e, curve_list[i], msg, public_key1, sign_str1, Verify, Q, sign2,(r,s))
        os.system("pause")



if __name__ == "__main__":
    check_my_implementations()
    # check_my_and_std_rep()