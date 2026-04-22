import requests

# Thay bằng Switch bạn muốn chặn (s1 hoặc s6)
SWITCH_ID = "of:0000000000000001" 
IP_KEO_TAN_CONG = "10.0.1.9"

def test_push_drop_rule():
    url = f"http://127.0.0.1:8181/onos/v1/flows/{SWITCH_ID}"
    
    flow_rule = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": SWITCH_ID,
        "treatment": {
            "instructions": []  # THỬ NGHIỆM MẢNG RỖNG TẠI ĐÂY
        },
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},
                {"type": "IPV4_SRC", "ip": f"{IP_KEO_TAN_CONG}/32"}
            ]
        }
    }
    
    print(f"Đang gửi lệnh DROP cho IP {IP_KEO_TAN_CONG} xuống {SWITCH_ID}...")
    try:
        response = requests.post(url, json=flow_rule, auth=('onos', 'rocks'), timeout=3)
        print(f"Mã trạng thái HTTP: {response.status_code}")
        
        if response.status_code in [200, 201, 202]:
            print("✅ ONOS ĐÃ CHẤP NHẬN LỆNH!")
        else:
            print(f"❌ LỖI ONOS TỪ CHỐI: {response.text}")
    except Exception as e:
        print(f"Lỗi kết nối: {e}")

if __name__ == "__main__":
    test_push_drop_rule()