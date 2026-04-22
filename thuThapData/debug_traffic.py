#!/usr/bin/env python3
"""
Script gỡ lỗi: Kiểm tra xem traffic đang từ đâu
Chạy: python3 debug_traffic.py
"""
import json
import time
import os

FIFO_PATH = "zeek_stream.json"

print("="*70)
print("🔍 DEBUG: Kiểm tra Traffic đang phát sinh từ đâu?")
print("="*70)
print(f"\n[1] Chờ FIFO {FIFO_PATH} được tạo...")

# Đợi FIFO được tạo
while not os.path.exists(FIFO_PATH):
    print(f"    (Chờ batPack tạo FIFO...)", end='\r')
    time.sleep(1)

print(f"\n[2] FIFO đã được tạo! Đang đọc dữ liệu...")
print(f"\n[3] DỮ LIỆU TRAFFIC (20 dòng đầu tiên):")
print("-"*70)

try:
    with open(FIFO_PATH, "r") as fifo:
        ips_src = {}
        ips_dst = {}
        
        for i in range(20):
            line = fifo.readline()
            if not line:
                print(f"    (Chưa có dữ liệu, chờ...)", end='\r')
                time.sleep(1)
                continue
            
            try:
                data = json.loads(line)
                src_ip = data.get("src_ip", data.get("ip", "?"))
                dst_ip = data.get("dst_ip", "?")
                
                # Thống kê
                ips_src[src_ip] = ips_src.get(src_ip, 0) + 1
                ips_dst[dst_ip] = ips_dst.get(dst_ip, 0) + 1
                
                print(f"  {i+1:2d}. SRC={src_ip:15s} → DST={dst_ip:15s}")
                
            except Exception as e:
                print(f"  {i+1:2d}. [LỖI] {e}")

    print("\n" + "-"*70)
    print("\n📊 THỐNG KÊ IP SOURCES:")
    for ip, count in sorted(ips_src.items(), key=lambda x: -x[1]):
        print(f"  {ip:20s} : {count:3d} lần")

    print("\n📊 THỐNG KÊ IP DESTINATIONS:")
    for ip, count in sorted(ips_dst.items(), key=lambda x: -x[1]):
        print(f"  {ip:20s} : {count:3d} lần")

    print("\n" + "="*70)
    print("✅ KẾT LUẬN:")
    
    # Kiểm tra dải IP
    normal_count = sum(1 for ip in ips_src if ip.startswith("10.0.2."))
    attack_count = sum(1 for ip in ips_src if ip.startswith("10.0.1."))
    bg_count = sum(1 for ip in ips_src if ip.startswith("10.0.0."))
    
    print(f"  • Traffic từ Normal clients (10.0.2.x): {normal_count}")
    print(f"  • Traffic từ Botnet (10.0.1.x): {attack_count}")
    print(f"  • Traffic từ Background (10.0.0.x): {bg_count}")
    
    if normal_count == 0 and attack_count == 0 and bg_count > 0:
        print(f"\n  ❌ VẤN ĐỀ: Traffic chỉ từ background services!")
        print(f"     → Lệnh Mininet không chạy đúng hoặc network routing sai")
        print(f"     → Hãy check:")
        print(f"        1. Chạy lệnh Mininet: py [net.get(f'h{{i}}').cmd(...) for i in range(60, 65)]")
        print(f"        2. Kiểm tra h60-h65 đang chạy: containernet> hosts h60")
        print(f"        3. Test ping: containernet> h60 ping -c 4 10.0.0.10")
    elif normal_count > 0:
        print(f"\n  ✅ TỐTLÀNH: Traffic từ Normal clients đã tới!")
    elif attack_count > 0:
        print(f"\n  ✅ TỐTLÀNH: Traffic từ Botnet đã tới!")
    
    print("\n" + "="*70)

except KeyboardInterrupt:
    print("\n\n[STOP] Debug dừng.")
except Exception as e:
    print(f"\n[LỖI] {e}")
