import random

def is_prime(n: int, k: int = 20) -> bool:
    """
    Проверка простоты числа с использованием теста Миллера-Рабина.
    Параметры:
        n: Число для проверки.
        k: Количество раундов тестирования.
    Возвращает:
        True, если число вероятно простое, иначе False.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Представим n-1 в виде (2^s * d)
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Проведем k раундов теста
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_prime(bit_length: int) -> int:
    """
    Генерация простого числа заданной длины с условием p ≡ 3 mod 4.
    Параметры:
        bit_length: Длина числа в битах.
    Возвращает:
        Простое число p.
    """
    while True:
        p = random.getrandbits(bit_length)
        p |= (1 << bit_length - 1) | 1  # Установка старшего и младшего бита
        if p % 4 == 3 and is_prime(p):
            return p

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Расширенный алгоритм Евклида.
    Параметры:
        a, b: Входные числа.
    Возвращает:
        (g, x, y): gcd(a, b), коэффициенты Безу (x, y).
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    g, x, y = g, y1, x1 - (a // b) * y1
    return g, x, y

def generate_keys(bit_length: int = 512) -> tuple[tuple[int, int, int, int, int], int]:
    """
    Генерация ключей для алгоритма Рабина.
    Параметры:
        bit_length: Длина модуля n в битах.
    Возвращает:
        private_key: Закрытый ключ (p, q, a, b, n)
        public_key: Открытый ключ (n)
    """
    half_len = bit_length // 2
    p = generate_prime(half_len)
    q = generate_prime(half_len)
    while p == q:
        q = generate_prime(half_len)

    n = p * q
    _, a, b = extended_gcd(p, q)
    return (p, q, a, b, n), n

def add_label(m: int) -> int:
    """Добавляет 16-битную метку к сообщению (старшие 16 бит)"""
    LABEL = 0b1010101010101010  # Фиксированный битовый шаблон AAaa в шестнадцатеричном виде
    return (m << 16) | LABEL

def remove_label(m_labeled: int) -> int | None:
    """Проверяет и удаляет метку, возвращает None если метка неверна"""
    LABEL = 0b1010101010101010
    label_part = m_labeled & 0xFFFF  # Младшие 16 бит
    original_m = m_labeled >> 16
    
    if label_part == LABEL:
        return original_m
    return None

def encrypt(m: int, n: int) -> int:
    """
    Шифрование сообщения с помощью открытого ключа.
    Параметры:
        m: Исходное сообщение (число).
        n: Открытый ключ.
    Возвращает:
        Зашифрованное сообщение.
    """
    return pow(m, 2, n)

def decrypt(c: int, private_key: tuple[int, int, int, int, int]) -> list[int]:
    """
    Дешифрование сообщения с помощью закрытого ключа.
    Параметры:
        c: Шифротекст.
        private_key: Закрытый ключ (p, q, a, b, n).
    Возвращает:
        Список из 4 возможных исходных сообщений.
    """
    p, q, a, b, n = private_key
    # Вычисление корней по модулям p и q
    r = pow(c, (p + 1) // 4, p)
    s = pow(c, (q + 1) // 4, q)
    # Комбинирование корней
    x = (a * p * s + b * q * r) % n
    y = (a * p * s - b * q * r) % n
    # Формирование всех четырех корней
    return [x % n, (-x) % n, y % n, (-y) % n]

# Пример использования
if __name__ == "__main__":
    # Генерация ключей
    private_key, public_key = generate_keys(bit_length=512)
    print(f"Открытый ключ (n): {public_key}")
    print(f"Закрытый ключ (p, q, a, b, n): {private_key}")

    # Шифрование и дешифрование
    message = 123456789  # Пример сообщения
    ciphertext = encrypt(message, public_key)
    print(f"Шифротекст: {ciphertext}")

    decrypted_messages = decrypt(ciphertext, private_key)
    print(f"Возможные исходные сообщения: {decrypted_messages}")
    print(f"Исходное сообщение присутствует в списке: {message in decrypted_messages}")