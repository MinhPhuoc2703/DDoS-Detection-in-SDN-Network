Hướng dẫn thu thập dữ liệu và kiểm thử hệ thống phát hiện/phòng chống DDoS
Bắt đầu tại thư mục gốc là Source.
1. Thu thập dữ liệu bình thường

Bước 1: Mở hai terminal song song 

Bước 2: Chạy Ryu Controller với file controllers/capture_normal.py
```bash
ryu-manager controllers/capture_normal.py
```

Bước 3: Chạy topology mạng Mininet với file mininet/topo.py
```bash
sudo python mininet/topo.py
```

Bước 4: Mở terminal của một host trong Mininet (ví dụ: h1)
```bash
xterm h1
```

Bước 5: Chạy file tạo lưu lượng bình thường trong terminal của h1
```bash
python utils/generate_normal_traffic.py
```

2. Thu thập dữ liệu tấn công DDoS

Bước 1: Mở hai terminal song song 

Bước 2: Chạy Ryu Controller với file controllers/capture_ddos.py
```bash
ryu-manager controllers/capture_ddos.py
```

Bước 3: Chạy topology mạng Mininet với file mininet/topo.py
```bash
sudo python mininet/topo.py
```

Bước 4: Mở terminal của một host trong Mininet (ví dụ: h1)
```bash
xterm h1
```

Bước 5: Chạy file tạo lưu lượng tấn công DDoS trong terminal của h1
```bash
python utils/generate_ddos_traffic.py
```

Bước 6: Dừng chương trình khi thu thập đủ dữ liệu bằng tổ hợp phím Ctrl + C.

3. Kiểm thử chương trình phát hiện DDoS

Bước 1: Chạy Ryu Controller với file controllers/DT_Controller.py
```bash
ryu-manager controllers/DT_Controller.py
```

Bước 2: Chạy topology mạng Mininet với file mininet/topo.py
```bash
sudo python mininet/topo.py
```

Bước 3: Kiểm thử bằng cách thực hiện lệnh ping hoặc hping3 để tạo tấn công DDoS và quan sát phản hồi của Controller.
```bash
ping <IP_Đích>
```
hoặc
```bash
hping3 -S --flood -p <Port> <IP_Đích>
```

4. Kiểm thử chương trình phòng chống DDoS

Bước 1: Chạy Ryu Controller với file controllers/DT_Controller_Mitigation.py
```bash
ryu-manager controllers/DT_Controller_Mitigation.py
```

Bước 2: Chạy topology mạng Mininet với file mininet/topo.py
```bash
sudo python mininet/topo.py
```

Bước 3: Kiểm thử bằng cách thực hiện lệnh ping hoặc hping3 để tạo tấn công DDoS và kiểm tra xem controller có thực hiện các biện pháp phòng chống hay không.
```bash
hping3 -S --flood -p <Port> <IP_Đích>
```
