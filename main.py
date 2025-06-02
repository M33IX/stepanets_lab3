from desx import CryptoManager as DESX
from rabin import (
    generate_keys as generate_rabin_keys, 
    encrypt as encrypt_rabin, 
    decrypt as decrypt_rabin
)
from rsa import (
    RSAKeyPair,
    RSASignature,
    sign_message,
    verify_signature,
    generate_rsa_keys
)

from typing import NamedTuple

class EncryptionResult(NamedTuple):
    encrypted_message: str
    encrypted_key: int
    signature: RSASignature

def encrypt(
    plaintext: str,
    rabin_public_key: int,
    rsa_key_pair: RSAKeyPair    
) -> EncryptionResult:
    
    desx = DESX()
    desx.generate_key()
    desx_key = desx.get_key()

    encrypted_message = desx.encrypt_message(plaintext)

    encrypted_desx_key = encrypt_rabin(desx_key, rabin_public_key)

    signature = sign_message(str(encrypted_desx_key), rsa_key_pair)

    return EncryptionResult(
        encrypted_message=encrypted_message,
        encrypted_key=encrypted_desx_key,
        signature=signature
    )

def decrypt(
        encryption_result: EncryptionResult,
        rabin_private_key: tuple[int, int, int, int, int],
        rsa_key_pair: RSAKeyPair
) -> str:
    encrypted_message, encrypted_desx_key, signature = encryption_result

    if not verify_signature(str(encrypted_desx_key), signature, rsa_key_pair):
        raise ValueError("Подпись неверна")
    
    desx_key = decrypt_rabin(encrypted_desx_key, rabin_private_key)

    desx = DESX(desx_key)

    decrypted_message = desx.decrypt_message(encrypted_message)

    return decrypted_message

if __name__ == "__main__":
    rabin_private, rabin_public = generate_rabin_keys()
    rsa_key_pair = generate_rsa_keys(1024)

    plaintext = "Test message"

    encrypted = encrypt(plaintext, rabin_public, rsa_key_pair)
    decrypted = decrypt(encrypted, rabin_private, rsa_key_pair)

    assert plaintext == decrypted

    print(f"Исходное сообщение: {plaintext}")
    print(f"\n Результат после шифрования: {encrypted} \n")
    print(f"Расшифрованное сообщение: {decrypted}")

    print(f"Результат соответствует исходному сообщению: {plaintext == decrypted}")