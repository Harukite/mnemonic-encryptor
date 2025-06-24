import argparse
import base64
import json
import os
import sys
from datetime import datetime
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp
import qrcode

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16  # 16 字节
NONCE_SIZE = 12  # 12 字节，AES-GCM 推荐


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 位
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_with_key(data: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    tag = ciphertext[-16:]
    ct = ciphertext[:-16]
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ct).decode(),
    }

def decrypt_with_key(enc_dict: dict, key: bytes) -> bytes:
    nonce = base64.b64decode(enc_dict['nonce'])
    tag = base64.b64decode(enc_dict['tag'])
    ct = base64.b64decode(enc_dict['ciphertext'])
    aesgcm = AESGCM(key)
    ciphertext = ct + tag
    data = aesgcm.decrypt(nonce, ciphertext, None)
    return data


def encrypt_mnemonic(mnemonic: str, password: str, use_totp: bool = True) -> dict:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    totp_enc = None
    if use_totp:
        # 生成 TOTP secret
        totp_secret = pyotp.random_base32()
        # 显示二维码
        uri = pyotp.totp.TOTP(totp_secret).provisioning_uri('user@mnemonic', issuer_name='MnemonicEncryptor')
        print('\n请用 Google Authenticator 或类似App扫描以下二维码绑定动态码：')
        qrcode.make(uri).show()
        print(f'如果无法扫码，可手动输入密钥: {totp_secret}\n')
        
        # 验证 TOTP 绑定
        totp = pyotp.TOTP(totp_secret)
        max_retries = 3
        retry_count = 0
        while retry_count < max_retries:
            print(f'\n为确保绑定成功，请输入手机App上的6位动态码（剩余尝试次数：{max_retries - retry_count}）：')
            code = input().strip()
            if totp.verify(code):
                print('动态码验证成功！继续加密...\n')
                break
            retry_count += 1
            if retry_count < max_retries:
                print(f'动态码验证失败！请等待新的动态码刷新后重试。')
            else:
                raise ValueError('动态码验证失败次数过多，加密终止。请确保正确绑定并等待新的动态码后重试。')
        
        # 用 key 加密 TOTP secret
        totp_enc = encrypt_with_key(totp_secret.encode('utf-8'), key)
    
    # 用 key 加密助记词
    mnemonic_enc = encrypt_with_key(mnemonic.encode('utf-8'), key)
    
    result = {
        'salt': base64.b64encode(salt).decode(),
        'mnemonic': mnemonic_enc,
        'created_at': datetime.utcnow().isoformat() + 'Z',
    }
    
    if totp_enc:
        result['totp'] = totp_enc
    
    return result


def decrypt_mnemonic(enc_dict: dict, password: str, use_totp: bool = True) -> str:
    try:
        salt = base64.b64decode(enc_dict['salt'])
        key = derive_key(password, salt)
        if use_totp:
            if 'totp' not in enc_dict:
                raise ValueError('该加密文件包含动态码验证，请使用 --use-totp 参数进行解密。')
            # 解密 TOTP secret
            totp_secret = decrypt_with_key(enc_dict['totp'], key).decode('utf-8')
            # 校验动态码
            totp = pyotp.TOTP(totp_secret)
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                code = input(f'请输入手机App上的6位动态码（剩余尝试次数：{max_retries - retry_count}）：')
                if totp.verify(code):
                    break
                retry_count += 1
                if retry_count < max_retries:
                    print(f'动态码验证失败！请等待新的动态码刷新后重试。')
                else:
                    raise ValueError('动态码验证失败次数过多，解密终止。请等待新的动态码后重试。')
        elif 'totp' in enc_dict:
            raise ValueError('该加密文件需要动态码验证，请添加 --use-totp 参数。')

        # 解密助记词
        mnemonic = decrypt_with_key(enc_dict['mnemonic'], key).decode('utf-8')
        return mnemonic
    except Exception as e:
        raise ValueError('解密失败，可能是密码/动态码错误或数据被篡改。') from e


def encrypt_mode(args):
    print('是否使用动态码验证？这将提供更高的安全性（y/n）：')
    use_totp = input().strip().lower() == 'y'
    args.use_totp = use_totp
    
    print('\n请输入助记词（用空格分隔）：')
    mnemonic = input().strip()
    password = getpass('请输入加密密码：')
    password2 = getpass('请再次输入密码：')
    if password != password2:
        print('两次输入的密码不一致，退出。')
        sys.exit(1)
    try:
        enc = encrypt_mnemonic(mnemonic, password, args.use_totp)
        out_file = 'mnemonic.enc.json'
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(enc, f, ensure_ascii=False, indent=2)
        print(f'加密完成，已保存到 {out_file}')
    except Exception as e:
        print(str(e))
        sys.exit(1)


def decrypt_mode(input_file, args):
    if not os.path.exists(input_file):
        print(f'文件不存在: {input_file}')
        sys.exit(1)
    with open(input_file, 'r', encoding='utf-8') as f:
        enc = json.load(f)
    
    # 检查文件是否包含动态码
    has_totp = 'totp' in enc
    if has_totp:
        print('该文件包含动态码验证，需要使用动态码进行解密。')
        args.use_totp = True
    else:
        print('该文件未使用动态码验证。')
        args.use_totp = False
    password = getpass('请输入解密密码：')
    try:
        mnemonic = decrypt_mnemonic(enc, password, args.use_totp)
        print('\n解密成功，助记词如下：')
        print(mnemonic)
    except Exception as e:
        print(str(e))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='助记词加密/解密工具（可选动态码认证）')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True, help='模式: encrypt 加密, decrypt 解密')
    parser.add_argument('--input', type=str, help='解密时输入的 JSON 文件名')
    parser.add_argument('--use-totp', action='store_true', help='是否使用动态码认证（默认不使用）')
    args = parser.parse_args()

    if args.mode == 'encrypt':
        encrypt_mode(args)
    elif args.mode == 'decrypt':
        if not args.input:
            print('解密模式需要 --input 参数指定加密文件')
            sys.exit(1)
        decrypt_mode(args.input, args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
