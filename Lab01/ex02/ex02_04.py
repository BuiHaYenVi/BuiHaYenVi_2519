#tạo một danh sách rỗng để lưu lết quả
j=[]
#duyệt qua tất cả các số trong đoạn từ 2000 đến 3200, kiểm tra xem số i có chia hết cho 7 và không phảiii là bội số của 5 khôg
for i in range(2000, 3200):
    if (i % 7 == 0) and (i % 5 != 0):
        j.append(str(i))
print (','.join(j))