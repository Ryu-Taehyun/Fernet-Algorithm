"""file_crypto.py 사용 예시: 파일 암호화 → 복호화 → 원본과 비교.

실행:
    python examples/encrypt_example.py

임시 폴더 안에서만 작업하므로 저장소에 키나 암호문이 남지 않습니다.
"""
import sys
import tempfile
from pathlib import Path

# 저장소 루트의 file_crypto.py를 import 할 수 있도록 경로 추가
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from file_crypto import decrypt_file, encrypt_file, generate_key  # noqa: E402


def demo_keyfile(workdir: Path, algo: str) -> None:
    """키 파일 방식: genkey로 만든 키로 암호화/복호화."""
    print(f"\n=== [{algo}] 키 파일 방식 ===")
    src = workdir / f"sample_{algo}.txt"
    src.write_text("안녕하세요, Fernet 파일 암호화 예시입니다.\n" * 3, encoding="utf-8")

    key_path = workdir / f"{algo}.key"
    key_path.write_bytes(generate_key(algo))
    print(f"[+] 키 생성: {key_path.name}")

    enc = workdir / f"{src.name}.enc"
    dec = workdir / f"{src.name}.dec"
    encrypt_file(str(src), str(enc), algo, key_path=str(key_path))
    decrypt_file(str(enc), str(dec), algo, key_path=str(key_path))

    check(src, enc, dec)

    # 다른 키로는 복호화되지 않는 것 확인
    wrong_key = workdir / f"{algo}_wrong.key"
    wrong_key.write_bytes(generate_key(algo))
    try:
        decrypt_file(str(enc), str(dec), algo, key_path=str(wrong_key))
    except ValueError as e:
        print(f"[ok] 잘못된 키 거부됨 -> {e}")


def demo_password(workdir: Path, algo: str) -> None:
    """비밀번호 방식: PBKDF2-HMAC-SHA256으로 키를 유도 (salt는 파일 헤더에 저장)."""
    print(f"\n=== [{algo}] 비밀번호 방식 ===")
    src = workdir / f"secret_{algo}.bin"
    src.write_bytes(bytes(range(256)) * 4)  # 바이너리 파일도 그대로 처리됨

    enc = workdir / f"{src.name}.enc"
    dec = workdir / f"{src.name}.dec"
    password = "correct horse battery staple"
    encrypt_file(str(src), str(enc), algo, password=password)
    decrypt_file(str(enc), str(dec), algo, password=password)

    check(src, enc, dec)

    try:
        decrypt_file(str(enc), str(dec), algo, password="wrong-password")
    except ValueError as e:
        print(f"[ok] 잘못된 비밀번호 거부됨 -> {e}")


def check(src: Path, enc: Path, dec: Path) -> None:
    original, cipher, restored = src.read_bytes(), enc.read_bytes(), dec.read_bytes()
    print(f"    원본 {len(original)}B / 암호문 {len(cipher)}B (헤더 {cipher[:4]!r})")
    assert original == restored, "복호화 결과가 원본과 다릅니다!"
    print("[ok] 복호화 결과가 원본과 동일합니다.")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for algo in ("fernet", "aes"):
            demo_keyfile(workdir, algo)
            demo_password(workdir, algo)
    print("\n모든 예시가 성공했습니다.")


if __name__ == "__main__":
    main()
