import random
from typing import Tuple, Optional

class RSAKeyPair:
    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.public_key = e
        self.private_key = d

class RSASignature:
    def __init__(self, signature: int):
        self.signature = signature

    def __repr__(self) -> str:
        return f"RSA Signature: {self.signature}"

def is_prime(n: int, k: int = 5) -> bool:
    """Проверка числа на простоту с использованием теста Миллера-Рабина."""
    if n <= 1:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n-2)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Генерация простого числа заданной битности."""
    while True:
        num = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(num):
            return num

def mod_inverse(a: int, m: int) -> Optional[int]:
    """Нахождение обратного элемента по модулю m."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def simple_hash(message: str) -> int:
    """Упрощенная хэш-функция (для демонстрации)."""
    return sum(ord(c) for c in message) % (2**32)

def generate_rsa_keys(bit_length: int = 1024) -> RSAKeyPair:
    """Генерация пары ключей для RSA."""
    # Генерация двух различных простых чисел
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    while p == q:
        q = generate_prime(bit_length // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Выбор открытой экспоненты
    e = 65537
    if phi % e == 0:
        e_list = [3, 5, 17, 257, 65537]
        for candidate in e_list:
            if phi % candidate != 0:
                e = candidate
                break
        else:
            e = 3
            while extended_gcd(e, phi)[0] != 1:
                e += 2
    
    # Вычисление секретной экспоненты
    d = mod_inverse(e, phi)
    if d is None:
        raise ValueError("Не удалось найти обратный элемент для e по модулю phi(n)")
    
    return RSAKeyPair(n, e, d)

def sign_message(message: str, key_pair: RSAKeyPair) -> RSASignature:
    """Подпись сообщения по алгоритму RSA."""
    h = simple_hash(message)
    # Проверка на слишком большое хэш-значение
    if h >= key_pair.n:
        h = h % key_pair.n
    
    signature = pow(h, key_pair.private_key, key_pair.n)
    return RSASignature(signature)

def verify_signature(message: str, signature: RSASignature, key_pair: RSAKeyPair) -> bool:
    """Проверка подписи RSA."""
    h = simple_hash(message)
    # Проверка на слишком большое хэш-значение
    if h >= key_pair.n:
        h = h % key_pair.n
    
    decrypted_hash = pow(signature.signature, key_pair.public_key, key_pair.n)
    return h == decrypted_hash

# Пример использования
if __name__ == "__main__":
    # Генерация ключей
    key_pair = generate_rsa_keys(1024)
    message = "Hello, RSA!"
    
    # Подпись сообщения
    signature = sign_message(message, key_pair)
    
    # Проверка подписи
    is_valid = verify_signature(message, signature, key_pair)
    print(f"Подпись {'верна' if is_valid else 'неверна'}!")
    
    # Проверка с измененным сообщением
    is_valid_fake = verify_signature("Fake message", signature, key_pair)
    print(f"Подпись для фейкового сообщения {'верна' if is_valid_fake else 'неверна'}!")
    
    # Проверка с измененной подписью
    tampered_signature = RSASignature(signature.signature + 1)
    is_valid_tampered = verify_signature(message, tampered_signature, key_pair)
    print(f"Подпись с измененной подписью {'верна' if is_valid_tampered else 'неверна'}!")