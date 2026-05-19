#!/usr/bin/env python3
"""
Load configuration từ .env file
Giúp bảo vệ IP private khi push Git
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    _DOTENV_AVAILABLE = True
except ImportError:
    _DOTENV_AVAILABLE = False

# Load .env file từ attack directory
env_path = Path(__file__).parent / ".env"

if _DOTENV_AVAILABLE:
    load_dotenv(env_path)
else:
    def _load_env_file(path: Path):
        if not path.exists():
            return
        with path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if (value.startswith("\"") and value.endswith("\"")) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                if key and os.getenv(key) is None:
                    os.environ[key] = value

    _load_env_file(env_path)

# Config mặc định
DEFAULT_CONFIG = {
    "TARGET_IP": "10.0.0.1",
    "TARGET_PORT": "80",
    "TARGET_PATH": "/",
    "TARGET_HOSTNAME": "example.com",
    "TARGET_METHOD": "POST",
    "USE_SSL": "False",
    "MAX_CONNECTIONS": "5000",
    "CONCURRENT_CONNECTIONS": "100",
    "DURATION": "60",
    "REQUESTS_PER_CONN": "1",
    "POST_CONTENT_LENGTH": "100000",
    "CHUNK_SIZE": "1024",
    "CHUNK_INTERVAL": "0.01",
}


def get_config(key, default=None):
    """
    Lấy giá trị config từ .env file hoặc mặc định
    """
    value = os.getenv(key)
    if value is None:
        value = DEFAULT_CONFIG.get(key, default)
    return value


def get_target_config():
    """Lấy config target attack"""
    return {
        "ip": get_config("TARGET_IP"),
        "port": int(get_config("TARGET_PORT", "80")),
        "path": get_config("TARGET_PATH", "/"),
        "hostname": get_config("TARGET_HOSTNAME"),
        "method": get_config("TARGET_METHOD", "POST").upper(),
        "use_ssl": get_config("USE_SSL", "False").lower() == "true",
        "max_connections": int(get_config("MAX_CONNECTIONS", "5000")),
        "concurrent_connections": int(get_config("CONCURRENT_CONNECTIONS", "100")),
        "duration": int(get_config("DURATION", "60")),
    }


def get_attack_config():
    """Lấy cấu hình tấn công bổ sung từ .env"""
    return {
        "requests_per_conn": int(get_config("REQUESTS_PER_CONN", "1")),
        "post_content_length": int(get_config("POST_CONTENT_LENGTH", "100000")),
        "chunk_size": int(get_config("CHUNK_SIZE", "1024")),
        "chunk_interval": float(get_config("CHUNK_INTERVAL", "0.01")),
    }


def validate_config():
    """Kiểm tra config có hợp lệ không"""
    config = get_target_config()
    
    if not config["ip"]:
        print("[!] ERROR: TARGET_IP chưa được cấu hình!")
        print("    Vui lòng tạo file .env hoặc sửa attack/.env.example thành .env")
        return False
    
    if config["ip"] == "10.0.0.1" or config["hostname"] == "example.com":
        print("[!] WARNING: Bạn đang sử dụng giá trị mặc định!")
        print("    Vui lòng sửa file .env với IP thực tế")
        return False
    
    return True


if __name__ == "__main__":
    print("Test config loading...")
    if validate_config():
        config = get_target_config()
        print(f"✓ TARGET_IP: {config['ip']}")
        print(f"✓ TARGET_PORT: {config['port']}")
        print(f"✓ TARGET_PATH: {config['path']}")
        print(f"✓ TARGET_HOSTNAME: {config['hostname']}")
        print(f"✓ USE_SSL: {config['use_ssl']}")
        print(f"✓ MAX_CONNECTIONS: {config['max_connections']}")
    else:
        print("✗ Config không hợp lệ!")
