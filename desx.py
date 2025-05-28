import random
from typing import Self

class DESCryptor:
    """Класс для выполнения шифрования/дешифрования по алгоритму DES"""
    
    # Константы перестановок и таблиц
    INITIAL_PERMUTATION_TABLE = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]
    
    FINAL_PERMUTATION_TABLE = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]
    
    EXPANSION_TABLE = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ]

    PC1_C = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36
    ]
    
    PC1_D = [
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    ]
    
    PC2_TABLE = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]
    
    P_BOX = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26,
        5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    
    S_BOXES = [
        [
            [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
            [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
            [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
            [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
        ],
        [
            [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
            [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
            [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
            [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
        ],
        [
            [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
            [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
            [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
            [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
        ],
        [
            [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
            [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
            [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
            [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
        ],
        [
            [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
            [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
            [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
            [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
        ],
        [
            [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
            [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
            [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
            [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
        ],
        [
            [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
            [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
            [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
            [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
        ],
        [
            [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
            [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
            [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
            [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
        ]
    ]
    
    ROUND_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    def __init__(self, key: int):
        self.key = key
        self.round_keys = self._generate_round_keys()

    def _permute(self, block: int, table: list[int], bits: int) -> int:
        """Выполняет перестановку битов согласно таблице"""
        result = 0
        for pos in table:
            original_pos = pos - 1
            bit = (block >> (bits - original_pos - 1)) & 1
            result = (result << 1) | bit
        return result

    def _left_rotate_28(self, bits: int, n: int) -> int:
        """Циклический сдвиг 28-битного числа влево"""
        return ((bits << n) | (bits >> (28 - n))) & 0x0FFFFFFF

    def _feistel_function(self, right_half: int, round_key: int) -> int:
        """Функция Фейстеля (расширение, смешивание с ключом, S-боксы, перестановка)"""
        # Расширение до 48 бит
        expanded = self._permute(right_half, self.EXPANSION_TABLE, 32)
        
        # XOR с ключом раунда
        mixed = expanded ^ round_key
        
        # Проход через S-боксы
        s_box_output = 0
        for s_box_num in range(8):
            # Выделяем 6 бит для текущего S-бокса
            bits = (mixed >> (42 - 6 * s_box_num)) & 0x3F
            row = ((bits >> 5) << 1) | (bits & 0x1)
            col = (bits >> 1) & 0xF
            s_value = self.S_BOXES[s_box_num][row][col]
            s_box_output = (s_box_output << 4) | s_value
        
        # Перестановка P-бокса
        return self._permute(s_box_output, self.P_BOX, 32)

    def _generate_round_keys(self) -> list[int]:
        """Генерирует 16 раундовых ключей по 48 бит"""
        # Первоначальная перестановка ключа (PC-1)
        key_permuted = self._permute(self.key, self.PC1_C + self.PC1_D, 64)
        
        c = (key_permuted >> 28) & 0x0FFFFFFF  # Первые 28 бит
        d = key_permuted & 0x0FFFFFFF          # Последние 28 бит
        
        round_keys = []
        for shift in self.ROUND_SHIFTS:
            # Циклический сдвиг
            c = self._left_rotate_28(c, shift)
            d = self._left_rotate_28(d, shift)
            
            # Комбинирование и перестановка (PC-2)
            combined = (c << 28) | d
            round_key = self._permute(combined, self.PC2_TABLE, 56)
            round_keys.append(round_key)
        
        return round_keys

    def process_block(self, block: int, encrypt: bool = True) -> int:
        """Обрабатывает один блок данных (64 бита)"""
        block = self._permute(block, self.INITIAL_PERMUTATION_TABLE, 64)
        
        left, right = (block >> 32) & 0xFFFFFFFF, block & 0xFFFFFFFF
        
        for i in range(16):
            if encrypt:
                key = self.round_keys[i]
            else:
                key = self.round_keys[15 - i]
            
            new_right = left ^ self._feistel_function(right, key)
            left, right = right, new_right
        
        combined = (right << 32) | left
        return self._permute(combined, self.FINAL_PERMUTATION_TABLE, 64)

class DESXCipher:
    """Реализация DES-X с CBC режимом"""
    
    def __init__(self, des_key: int, k1: int, k2: int, iv: int):
        self.cryptor = DESCryptor(des_key)
        self.k1 = k1
        self.k2 = k2
        self.iv = iv
        self.prev_block = iv

    def _process_chunk(self, chunk: bytes) -> bytes:
        """Обрабатывает 8-байтовый чанк данных"""
        if len(chunk) != 8:
            chunk = chunk.ljust(8, b'\x00')
        return chunk

    def encrypt(self, data: bytes) -> bytes:
        """Шифрует данные"""
        result = bytearray()
        for i in range(0, len(data), 8):
            chunk = self._process_chunk(data[i:i+8])
            block = int.from_bytes(chunk, 'big')
            
            block ^= self.prev_block
            block ^= self.k1
            encrypted = self.cryptor.process_block(block)
            encrypted ^= self.k2
            
            self.prev_block = encrypted
            result.extend(encrypted.to_bytes(8, 'big'))
        
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Дешифрует данные"""
        result = bytearray()
        prev_cipher_block = self.iv
        
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]
            encrypted = int.from_bytes(chunk, 'big')
            
            decrypted = encrypted ^ self.k2
            decrypted = self.cryptor.process_block(decrypted, encrypt=False)
            decrypted ^= self.k1
            decrypted ^= prev_cipher_block
            
            prev_cipher_block = encrypted
            result.extend(decrypted.to_bytes(8, 'big'))
        
        return bytes(result).rstrip(b'\x00')

class CryptoManager:
    """Управление криптографическими операциями"""
    
    def __init__(self, key: int | None = None):
        self.iv = 0x0123456789ABCDEF
        self.k1 = 0xFEDCBA9876543210
        self.k2 = 0x543210FEDCBA9876
        self.des_key = key

    @classmethod
    def with_key(cls, key: int) -> Self:
        return cls(key)

    def get_key(self) -> int:
        if not self.des_key:
            self.generate_key()
        return self.des_key #type:ignore

    def generate_key(self) -> None:
        """Генерирует новый DES-ключ"""
        self.des_key = random.getrandbits(64)

    def encrypt_message(self, message: str) -> str:
        """Шифрует сообщение"""
        if not self.des_key:
            raise ValueError("Ключ не установлен")
        
        cipher = DESXCipher(self.des_key, self.k1, self.k2, self.iv)
        encrypted = cipher.encrypt(message.encode())
        return encrypted.hex()

    def decrypt_message(self, encrypted_hex: str) -> str:
        """Дешифрует сообщение"""
        if not self.des_key:
            raise ValueError("Ключ не установлен")
        
        cipher = DESXCipher(self.des_key, self.k1, self.k2, self.iv)
        encrypted = bytes.fromhex(encrypted_hex)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode().strip('\x00')

def main():
    manager = CryptoManager()
    
    while True:
        print("\nМеню:")
        print("1. Сгенерировать новый ключ")
        print("2. Зашифровать сообщение")
        print("3. Расшифровать сообщение")
        print("4. Выход")
        
        choice = input("Выберите действие: ")
        
        if choice == '1':
            manager.generate_key()
            print(manager.get_key())
        elif choice == '2':
            message = input("Введите сообщение: ")
            encrypted = manager.encrypt_message(message)
            print("\nЗашифрованное сообщение:", encrypted)
        elif choice == '3':
            encrypted = input("Введите зашифрованное сообщение (hex): ")
            try:
                decrypted = manager.decrypt_message(encrypted)
                print("\nРасшифрованное сообщение:", decrypted)
            except Exception as e:
                print("Ошибка дешифрования:", e)
        elif choice == '4':
            break
        else:
            print("Некорректный выбор")

if __name__ == "__main__":
    main()