# Fernet-Algorithm

Python `cryptography` 라이브러리로 만든 단일 파일 암호화·복호화 도구입니다. Fernet과 AES-256-GCM을 지원합니다. 학습과 테스트 용도로 만들었습니다.

## 설치

```bash
pip install cryptography
```

## 사용법

```bash
# 키 생성
python file_crypto.py genkey --algo fernet -o fernet.key

# 암호화 (원본은 그대로 두고 <파일>.enc 생성)
python file_crypto.py encrypt --algo fernet -k fernet.key sample.txt

# 복호화 (<파일>.dec 생성)
python file_crypto.py decrypt --algo fernet -k fernet.key sample.txt.enc
```

- `--algo aes`로 바꾸면 AES-256-GCM을 씁니다. AES 키는 `genkey --algo aes`로 따로 만들어야 합니다.
- `-k` 대신 `-p "비밀번호"`를 쓰면 PBKDF2-HMAC-SHA256으로 키를 만들어 씁니다.

## 예시 코드

`examples/encrypt_example.py`는 `file_crypto.py`의 함수를 직접 import 해서 Fernet·AES-GCM 각각 키 파일 방식과 비밀번호 방식으로 암호화→복호화→원본 비교를 해 봅니다. 잘못된 키·비밀번호가 거부되는지도 확인합니다. 임시 폴더에서만 작업하므로 저장소에 파일이 남지 않습니다.

```bash
python examples/encrypt_example.py
```

## 알고리즘

| 방식 | 구성 | 무결성 검증 |
|---|---|---|
| Fernet | AES-128-CBC + HMAC-SHA256 | HMAC |
| AES-GCM | AES-256-GCM, 12바이트 랜덤 nonce | GCM 태그 |

키 파일(`*.key`)은 `.gitignore`로 저장소에서 제외됩니다. 키를 잃어버리면 그 키로 암호화한 파일은 복구할 수 없습니다.
