```
import base64

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print('请安装加解密库pycryptodome')


class AesSample(object):
    def __init__(self):
        self.key = 'MbQeThWmZq4t6w9x'.encode('utf-8')
        self.iv = 'MbQeThWmZq4t6w9x'.encode('utf-8')
        self.mode = AES.MODE_CBC

    def encode(self, data):
        cipher = AES.new(self.key, self.mode, self.iv)
        pad_pkcs7 = pad(data.encode('utf-8'), AES.block_size, style='pkcs7')
        result = base64.encodebytes(cipher.encrypt(pad_pkcs7))
        encrypted_text = str(result, encoding='utf-8').replace('\n', '')
        return encrypted_text

    def decode(self, data):
        cipher = AES.new(self.key, self.mode, self.iv)
        base64_decrypted = base64.decodebytes(data.encode('utf-8'))
        una_pkcs7 = unpad(cipher.decrypt(base64_decrypted), AES.block_size, style='pkcs7')
        decrypted_text = str(una_pkcs7, encoding='utf-8')
        return decrypted_text


if __name__ == '__main__':
    blog = AesSample()
    data1 = '{"operating_subject_id":107}'
    data2 = '8Q9WfnnVlJiO1Ea0RuMKOmyyRNFlDezsdcm6g1DaCqw='
    print('加密结果：', blog.encode(data1))
    print('解密结果：', blog.decode(data2))
```