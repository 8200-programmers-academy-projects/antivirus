import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

API_KEY_FILE_PATH = "api_key.json"
PIN_BYTES_LENGTH = 4
NONCE_LENGTH = 12


# AES encryption, key as SHA256 pin hash
def aes_encrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    nonce = os.urandom(NONCE_LENGTH)
    aes = AESGCM(key)

    ciphertext = aes.encrypt(nonce, data, None)
    return nonce + ciphertext


# AES decryption function, key as SHA256 pin hash
def aes_decrypt(encrypted: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    nonce = encrypted[:NONCE_LENGTH]
    ciphertext = encrypted[NONCE_LENGTH:]

    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


class VirusTotalApiStorage:
    def __init__(self):
        pass

    def set_key(self, key: str):
        try:
            pin = int(
                input(
                    f"enter pin for encrypting api key (number under 2^{PIN_BYTES_LENGTH*8}({2**(PIN_BYTES_LENGTH*8)})): "
                )
            )
        except Exception:
            print("not valid pin, try again")
            return

        pin_hash = hashlib.sha256(
            pin.to_bytes(PIN_BYTES_LENGTH, byteorder="big", signed=False)
        ).digest()

        encrypted_key = aes_encrypt(key.encode(), pin_hash)

        data = {
            "pin_sha256_double_hash": hashlib.sha256(pin_hash).hexdigest(),
            "encrypted_key": encrypted_key.hex(),
        }

        json_data = json.dumps(data)

        with open(API_KEY_FILE_PATH, "w") as f:
            f.seek(0)
            f.write(json_data)

        print("key saved")

    def get_key(self) -> str:
        try:
            with open(API_KEY_FILE_PATH, "r") as f:
                data = json.load(f)
        except Exception:
            print("key file not found or corrupted")
            return ""

        encrypted_key_hex = data.get("encrypted_key")
        double_hash_stored = data.get("pin_sha256_double_hash")

        if not encrypted_key_hex or not double_hash_stored:
            print("key data incomplete")
            return ""

        encrypted_key = bytes.fromhex(encrypted_key_hex)

        try:
            pin = int(input(f"enter pin to decrypt api key: "))
        except Exception:
            print("not valid pin")
            return ""

        pin_hash = hashlib.sha256(
            pin.to_bytes(PIN_BYTES_LENGTH, byteorder="big", signed=False)
        ).digest()

        if hashlib.sha256(pin_hash).hexdigest() != double_hash_stored:
            print("wrong pin")
            return ""

        try:
            decrypted_key_bytes = aes_decrypt(encrypted_key, pin_hash)
        except Exception:
            print("decryption failed")
            return ""

        return decrypted_key_bytes.decode()
