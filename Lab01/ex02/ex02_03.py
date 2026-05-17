#Nhập số từ người dùng
so = int(input("nhập một số nguyên: "))
#Kiểm tra xem số đó có phải số chẵn hay không
if so % 2 == 0:
    print(so, "là số chẵn.")
else:
    print(so, "không phải số chẵn.")