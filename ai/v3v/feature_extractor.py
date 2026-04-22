'''4. feature_extractor.py -> LỖI THỜI (HÃY XÓA/BỎ QUA)

Đánh giá: File này dùng thư viện pyshark để đọc file .pcap và trích xuất 20 đặc trưng. Nó thuộc về một hướng tiếp cận cũ kĩ và chậm chạp. Ở v4, chúng ta đã dùng NFStreamer bắt data trực tiếp trên RAM siêu tốc.

Kết luận: Không còn giá trị sử dụng trong kiến trúc v4.'''
import pyshark
import pandas as pd
import numpy as np
import ipaddress

def ip_to_int(ip_str):
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except:
        return 0

def extract_features(pcap_path, output_csv):
    print(f"⏳ Đang trích xuất đặc trưng từ {pcap_path}...")
    capture = pyshark.FileCapture(pcap_path)
    records = []

    for pkt in capture:
        try:
            if 'IP' not in pkt: continue
            
            # Khởi tạo bản ghi với 20 đặc trưng (đã thống nhất trong NUM_FEATURES)
            feature_row = {
                "timestamp": float(pkt.sniff_timestamp),
                "src_ip": ip_to_int(pkt.ip.src),
                "dst_ip": ip_to_int(pkt.ip.dst),
                "protocol": int(pkt.ip.proto),
                "length": int(pkt.length),
                "src_port": int(pkt[pkt.transport_layer].srcport) if hasattr(pkt, 'transport_layer') else 0,
                "dst_port": int(pkt[pkt.transport_layer].dstport) if hasattr(pkt, 'transport_layer') else 0,
                # Thêm các đặc trưng khác cho đủ 20 trường như trong master_dataset
                # ... (Các trường này cần khớp chính xác với thứ tự cột trong master_dataset)
            }
            records.append(feature_row)
        except Exception as e:
            continue

    df = pd.DataFrame(records)
    df.to_csv(output_csv, index=False)
    print(f"✅ Đã lưu {len(df)} bản ghi vào {output_csv}")

if __name__ == "__main__":
    extract_features("dataset/traffic.pcap", "dataset/features.csv")