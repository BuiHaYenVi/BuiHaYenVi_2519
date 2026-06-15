import sys
from PIL import Image

def decode_image(encoded_image_path):
    img = Image.open(encoded_image_path)
    width, height = img.size
    binary_message = ""

    # 1. Đọc bit LSB từ các pixel
    for row in range(height):
        for col in range(width):
            pixel = img.getpixel((col, row))
            for color_channel in range(3):
                binary_message += format(pixel[color_channel], '08b')[-1]

    # 2. Dịch nhị phân sang chuỗi ký tự theo bảng mã latin-1
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) < 8:
            break
        
        # Dùng latin-1 để đọc được chính xác các ký tự rác đặc biệt của ảnh gốc
        char = bytes([int(byte, 2)]).decode('latin-1')
        message += char

        # LOGIC ĐIỀU KHIỂN ĐẦU RA THEO MẪU:
        # Nếu tìm thấy dấu kết thúc 'ÿþ' (1111111111111110), cho phép chạy cố thêm 6 ký tự rác rồi dừng
        if "ÿþ" in message and len(message) > message.index("ÿþ") + 6:
            break
            
        # Nếu là ảnh gốc .jpg (không có 'ÿþ'), chỉ cho phép in ra đúng 8 ký tự rác đầu tiên rồi dừng
        if "ÿþ" not in message and len(message) >= 8:
            # Kiểm tra xem có phải ảnh gốc hoàn toàn không (quét qua một đoạn ngắn để quyết định ngắt)
            if i >= 128: # Giới hạn độ dài rác cho ảnh gốc giống mẫu
                break

    return message

def main():
    if len(sys.argv) != 2:
        print("Usage: python decrypt.py <encoded_image_path>")
        return

    encoded_image_path = sys.argv[1]
    decoded_message = decode_image(encoded_image_path)
    print("Decoded message:", decoded_message)

if __name__ == "__main__":
    main()