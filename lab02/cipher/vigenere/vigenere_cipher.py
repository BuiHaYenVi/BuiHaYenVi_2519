class VigenereCipher:
    def __init__(self):
        pass

    def vigenere_encrypt(self, plain_text, key):
        encrypted_text = ""
        key_index = 0
        
        for char in plain_text:
            if char.isalpha():
                # Tính toán giá trị dịch chuyển dựa trên ký tự tương ứng của key
                key_shift = ord(key[key_index % len(key)].upper()) - ord('A')
                
                if char.isupper():
                    # Công thức mã hóa cho chữ hoa
                    encrypted_text += chr((ord(char) - ord('A') + key_shift) % 26 + ord('A'))
                else:
                    # Công thức mã hóa cho chữ thường
                    encrypted_text += chr((ord(char) - ord('a') + key_shift) % 26 + ord('a'))
                
                key_index += 1
            else:
                # Giữ nguyên các ký tự không phải chữ cái (khoảng trắng, số,...)
                encrypted_text += char
                
        return encrypted_text

    def vigenere_decrypt(self, encrypted_text, key):
        decrypted_text = ""
        key_index = 0
        
        for char in encrypted_text:
            if char.isalpha():
                # Tính toán giá trị dịch chuyển (ngược lại)
                key_shift = ord(key[key_index % len(key)].upper()) - ord('A')
                
                if char.isupper():
                    # Công thức giải mã cho chữ hoa
                    decrypted_text += chr((ord(char) - ord('A') - key_shift) % 26 + ord('A'))
                else:
                    # Công thức giải mã cho chữ thường
                    decrypted_text += chr((ord(char) - ord('a') - key_shift) % 26 + ord('a'))
                
                key_index += 1
            else:
                decrypted_text += char
                
        return decrypted_text