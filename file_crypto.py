import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC_FERNET = b"FRN1"
MAGIC_AES = b"AES1"
MODE_KEYFILE = 0
MODE_PASSWORD = 1
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 600_000

# Base64 기반 텍스트 변환
def generate_key(algo: str) -> bytes:
    if algo == "fernet":
        return Fernet.generate_key()  # 이미 urlsafe base64 (32바이트 키)
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256))

# 키 로드
def load_key(path: str, algo: str) -> bytes:
    raw = Path(path).read_bytes().strip()
    if algo == "fernet":
        Fernet(raw)
        return raw
    key = base64.urlsafe_b64decode(raw)
    if len(key) != 32:
        raise ValueError("AES 키는 32바이트(256비트)여야 합니다.")
    return key

# 키 생성
def derive_key(password: str, salt: bytes, algo: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key) if algo == "fernet" else key


# 암호화
def encrypt_bytes(data: bytes, algo: str, key: bytes) -> bytes:
    if algo == "fernet":
        return Fernet(key).encrypt(data)
    nonce = os.urandom(NONCE_SIZE)  # 같은 키로 nonce 재사용 금지
    return nonce + AESGCM(key).encrypt(nonce, data, None)

# 복호화
def decrypt_bytes(blob: bytes, algo: str, key: bytes) -> bytes:
    if algo == "fernet":
        return Fernet(key).decrypt(blob)
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, None)

# 파일 암호화
def encrypt_file(src: str, dst: str, algo: str, key_path=None, password=None):
    magic = MAGIC_FERNET if algo == "fernet" else MAGIC_AES
    data = Path(src).read_bytes()

    if password is not None:
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt, algo)
        header = magic + bytes([MODE_PASSWORD]) + salt
    else:
        key = load_key(key_path, algo)
        header = magic + bytes([MODE_KEYFILE])

    Path(dst).write_bytes(header + encrypt_bytes(data, algo, key))
    print(f"[+] 암호화 완료 ({algo}): {src} -> {dst}")

# 파일 복호화
def decrypt_file(src: str, dst: str, algo: str, key_path=None, password=None):
    blob = Path(src).read_bytes()
    expected = MAGIC_FERNET if algo == "fernet" else MAGIC_AES
    if blob[:4] != expected:
        raise ValueError(f"이 파일은 {algo} 형식으로 암호화된 파일이 아닙니다.")

    mode = blob[4]
    body = blob[5:]
    if mode == MODE_PASSWORD:
        if password is None:
            raise ValueError("비밀번호로 암호화된 파일입니다. -p 옵션을 사용하세요.")
        salt, body = body[:SALT_SIZE], body[SALT_SIZE:]
        key = derive_key(password, salt, algo)
    else:
        if key_path is None:
            raise ValueError("키 파일로 암호화된 파일입니다. -k 옵션을 사용하세요.")
        key = load_key(key_path, algo)

    try:
        plain = decrypt_bytes(body, algo, key)
    except (InvalidToken, InvalidTag):
        raise ValueError("복호화 실패: 키/비밀번호가 틀렸거나 파일이 변조되었습니다.")

    Path(dst).write_bytes(plain)
    print(f"[+] 복호화 완료 ({algo}): {src} -> {dst}")


# 콘솔
def main():
    p = argparse.ArgumentParser(description="Fernet / AES-GCM 파일 암호화 도구 (테스트용)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkey", help="랜덤 키 생성")
    g.add_argument("--algo", choices=["fernet", "aes"], required=True)
    g.add_argument("-o", "--out", required=True, help="키 저장 경로")

    for name in ("encrypt", "decrypt"):
        s = sub.add_parser(name)
        s.add_argument("--algo", choices=["fernet", "aes"], required=True)
        s.add_argument("file", help="대상 파일")
        s.add_argument("-o", "--out", help="출력 경로 (기본: .enc / .dec)")
        grp = s.add_mutually_exclusive_group(required=True)
        grp.add_argument("-k", "--key", help="키 파일 경로")
        grp.add_argument("-p", "--password", help="비밀번호 (PBKDF2로 키 유도)")

    a = p.parse_args()

    try:
        if a.cmd == "genkey":
            Path(a.out).write_bytes(generate_key(a.algo))
            print(f"[+] {a.algo} 키 생성: {a.out}  (안전하게 보관하세요)")
        elif a.cmd == "encrypt":
            out = a.out or a.file + ".enc"
            encrypt_file(a.file, out, a.algo, a.key, a.password)
        else:
            out = a.out or (a.file[:-4] if a.file.endswith(".enc") else a.file) + ".dec"
            decrypt_file(a.file, out, a.algo, a.key, a.password)
    except (ValueError, FileNotFoundError) as e:
        print(f"[!] 오류: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
