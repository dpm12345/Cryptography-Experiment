'''
Author       : dpm12345 1006975692@qq.com
Github       : https://github.com/dpm12345
Date         : 2023-04-27 09:42:08
LastEditors  : dpm12345 1006975692@qq.com
LastEditTime : 2023-05-17 01:56:39
Description  : 
'''
import SM3
import SM4
import HMAC
import hmac as Hmac

if __name__ == '__main__':

    # 数据准备
    with open('./test.txt',"r",encoding='utf-8') as f:
        plain_text = f.read()
    sm4 = SM4.SM4()
    sm3 = SM3.SM3()
    hmac = HMAC.HMAC(sm3,name="hash")
    key = "It's a secret key".encode()
    another_hmac = Hmac.HMAC(key,plain_text.encode(),"sm3")

    # 加密文本并计算HMAC值
    ciper_text = sm4.encrypt_cbc(plain_text,key)
    hmac_val = hmac.run(plain_text,key)

    # 输出加密文本和HMAC值
    print("加密后的文本(字节串制):",ciper_text,sep="\n",end="\n\n")
    print("加密后的文本(十六进制):",ciper_text.hex(),sep="\n",end="\n\n")
    print("明文的HMAC值(内置库):",another_hmac.hexdigest(),sep="\n")
    print("明文的HMAC值(自行编写):",hmac_val,sep="\n",end="\n\n")

    # 解密文本
    decrypt_plain_text = sm4.decrypt_cbc(ciper_text,key)
    
    # 如果解密后的文本的HMAC值与所给HMAC值相同，输出True和明文内容
    if hmac.run(decrypt_plain_text,key) == hmac_val:
        print(True,end=" ")
        print("明文为:",decrypt_plain_text.decode(),sep="\n")
    else:
        print(False)
