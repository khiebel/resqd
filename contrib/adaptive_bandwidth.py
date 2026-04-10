"""
Adaptive Bandwidth Controller

RTT-based congestion-aware upload throttling, inspired by LEDBAT (RFC 6817).

Core principle: measure the RTT of each transfer block. Rising RTT means
congestion from ANY source (other apps, other users, WAN saturation).
Back off when RTT rises above baseline. Speed up when it returns.
Never inspects other traffic — the RTT encodes everything end-to-end.

Usage:
    from adaptive_bandwidth import BandwidthController

    bw = BandwidthController(
        target_host="s3.us-east-1.amazonaws.com",
        max_bandwidth=4_000_000,  # 4 MB/s total pipe
        work_rate=0.75,           # use 75% of available
    )

    # Before each transfer block:
    delay = bw.get_inter_block_delay()
    if delay > 0:
        time.sleep(delay)

    # After each transfer block:
    bw.report_block(bytes_sent, elapsed_seconds)

    # For boto3 S3 uploads:
    config = bw.get_transfer_config()
"""

import time
import socket
import struct
import os
import threading
import statistics
from datetime import datetime
from collections import deque
from dataclasses import dataclass


# ============ ICMP Ping (for baseline RTT) ============

def _checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ping_rtt(host: str, timeout: float = 2.0) -> float:
    """
    Measure ICMP ping RTT to a host. Returns RTT in seconds, or -1 on failure.
    Requires raw socket (root/admin) — falls back to TCP connect timing if unavailable.
    """
    # Try ICMP first
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        dest = socket.gethostbyname(host)
        pid = os.getpid() & 0xFFFF
        seq = 1

        # Build ICMP echo request
        header = struct.pack('!BBHHH', 8, 0, 0, pid, seq)
        payload = struct.pack('!d', time.time())
        chk = _checksum(header + payload)
        header = struct.pack('!BBHHH', 8, 0, chk, pid, seq)

        start = time.perf_counter()
        sock.sendto(header + payload, (dest, 1))
        sock.recvfrom(1024)
        rtt = time.perf_counter() - start
        sock.close()
        return rtt
    except (PermissionError, OSError):
        pass

    # Fallback: TCP connect timing to port 443
    try:
        dest = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.connect((dest, 443))
        rtt = time.perf_counter() - start
        sock.close()
        return rtt
    except Exception:
        return -1


# ============ Data Structures ============

@dataclass
class BlockSample:
    """One transfer block measurement."""
    timestamp: float
    block_size: int       # bytes transferred
    elapsed: float        # seconds for this block
    rtt: float            # measured RTT to target (seconds)
    throughput: float     # block_size / elapsed (bytes/sec)
    delay_applied: float  # inter-block delay we inserted (seconds)


class BandwidthController:
    """
    Adaptive bandwidth controller using LEDBAT-style congestion detection.

    Algorithm:

    1. ICMP ping to target establishes baseline RTT (the "no congestion" floor)
    2. Each transfer block's RTT is compared to baseline
    3. If RTT rises above baseline by >40%, congestion is detected — insert
       inter-block delays to reduce throughput
    4. If RTT drops back near baseline, reduce delays to speed up
    5. WorkRate caps maximum utilization as a percentage of pipe capacity

    Key insight: RTT encodes ALL congestion sources end-to-end. We never
    need to inspect NIC counters or other processes. A congested router
    5 hops away shows up as increased RTT just like local contention.

    The controller voluntarily de-prioritizes itself when it detects
    congestion — yielding bandwidth to interactive traffic automatically.
    """

    def __init__(
        self,
        target_host: str = "s3.us-east-1.amazonaws.com",
        max_bandwidth: int = 4_000_000,      # total pipe capacity (bytes/sec)
        work_rate: float = 0.75,             # use this % of available bandwidth
        work_rate_schedule: dict = None,     # hourly overrides: {hour: rate}
        min_speed: int = 200_000,            # floor: 200 KB/s
        block_size: int = 128 * 1024,        # initial block size for chunk sizing
        sample_window: int = 40,             # rolling window of samples
        congestion_threshold: float = 1.4,   # RTT ratio above this = congested
        clear_threshold: float = 1.15,       # RTT ratio below this = clear
        ramp_factor: float = 1.08,           # speed up by 8% per clear reading
        backoff_factor: float = 0.5,         # halve speed on congestion (LEDBAT)
        baseline_refresh: int = 300,         # re-ping baseline every 5 min
    ):
        self.target_host = target_host
        self.max_bandwidth = max_bandwidth
        self.work_rate = work_rate
        self.work_rate_schedule = work_rate_schedule or {}
        self.min_speed = min_speed
        self.block_size = block_size
        self.sample_window = sample_window
        self.congestion_threshold = congestion_threshold
        self.clear_threshold = clear_threshold
        self.ramp_factor = ramp_factor
        self.backoff_factor = backoff_factor
        self.baseline_refresh = baseline_refresh

        # State
        self._lock = threading.Lock()
        self._samples: deque = deque(maxlen=sample_window)
        self._baseline_rtt: float = 0          # minimum RTT (no-congestion floor)
        self._baseline_rtts: deque = deque(maxlen=60)  # last 5 min of baseline pings
        self._inter_block_delay: float = 0     # current delay between blocks (sec)
        self._current_speed: int = int(max_bandwidth * work_rate)
        self._state: str = "starting"
        self._congestion_streak: int = 0
        self._clear_streak: int = 0
        self._last_baseline_check: float = 0
        self._total_bytes: int = 0
        self._total_time: float = 0
        self._started: float = time.time()

        # Establish initial baseline
        self._establish_baseline()

    def _establish_baseline(self):
        """Ping target to establish no-congestion RTT baseline."""
        rtts = []
        for _ in range(5):
            rtt = ping_rtt(self.target_host, timeout=2.0)
            if rtt > 0:
                rtts.append(rtt)
            time.sleep(0.2)

        if rtts:
            self._baseline_rtt = min(rtts)  # minimum = no congestion
            for r in rtts:
                self._baseline_rtts.append(r)
            self._state = "ramping"
        else:
            # Can't ping — use assumed baseline, will calibrate from transfers
            self._baseline_rtt = 0.05  # assume 50ms
            self._state = "calibrating"

    def _refresh_baseline(self):
        """Periodically re-ping to track baseline drift (e.g., route changes)."""
        now = time.time()
        if now - self._last_baseline_check < self.baseline_refresh:
            return
        self._last_baseline_check = now

        rtt = ping_rtt(self.target_host, timeout=2.0)
        if rtt > 0:
            self._baseline_rtts.append(rtt)
            # Baseline = minimum of recent pings (LEDBAT: min over last 10 min)
            self._baseline_rtt = min(self._baseline_rtts)

    @property
    def current_work_rate(self) -> float:
        """Work rate for current hour, with schedule overrides."""
        hour = datetime.now().hour
        return self.work_rate_schedule.get(hour, self.work_rate)

    @property
    def current_speed(self) -> int:
        """Current allowed speed in bytes/sec."""
        with self._lock:
            return self._current_speed

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def report_block(self, bytes_transferred: int, elapsed: float):
        """
        Report a completed transfer block. This is the core measurement.

        Each block's effective RTT (elapsed / bytes * block_size)
        is compared to the baseline. The ratio drives speed adjustment.

        Args:
            bytes_transferred: bytes sent/received in this block
            elapsed: wall-clock seconds for this block (includes network + disk I/O)
        """
        if elapsed <= 0 or bytes_transferred <= 0:
            return

        throughput = bytes_transferred / elapsed

        # Estimate per-block RTT from transfer timing
        # For a block of size B at link capacity C, ideal time = B/C
        # Actual time = elapsed. Extra time = queueing/congestion.
        # We use elapsed directly as a proxy for RTT at the block level.
        # Normalize: block_rtt = elapsed * (standard_block_size / actual_size)
        # This makes RTT comparable across different block sizes.
        normalized_rtt = elapsed * (self.block_size / bytes_transferred)

        sample = BlockSample(
            timestamp=time.time(),
            block_size=bytes_transferred,
            elapsed=elapsed,
            rtt=normalized_rtt,
            throughput=throughput,
            delay_applied=self._inter_block_delay,
        )

        with self._lock:
            self._samples.append(sample)
            self._total_bytes += bytes_transferred
            self._total_time += elapsed

            # Calibrate baseline from early transfers if ICMP failed
            if self._state == "calibrating" and len(self._samples) >= 5:
                # Use minimum normalized RTT as baseline
                self._baseline_rtt = min(s.rtt for s in self._samples)
                self._state = "ramping"

            # Refresh baseline periodically
            self._refresh_baseline()

            # Adjust speed
            if len(self._samples) >= 3:
                self._adjust()

    def _adjust(self):
        """
        Core LEDBAT-style algorithm: adjust inter-block delay based on
        RTT ratio to baseline.
        """
        recent = list(self._samples)[-10:]
        if not recent or self._baseline_rtt <= 0:
            return

        # Current delay = median RTT of recent blocks vs baseline
        current_rtt = statistics.median(s.rtt for s in recent)
        rtt_ratio = current_rtt / self._baseline_rtt

        # LEDBAT-style: calculate queueing delay
        queuing_delay = current_rtt - self._baseline_rtt
        target_delay = self._baseline_rtt * (self.congestion_threshold - 1)

        max_speed = int(self.max_bandwidth * self.current_work_rate)

        if rtt_ratio > self.congestion_threshold:
            # CONGESTION: RTT significantly above baseline
            # Back off — halve speed on congestion detection
            self._congestion_streak += 1
            self._clear_streak = 0
            self._state = "backing_off"

            self._current_speed = max(
                int(self._current_speed * self.backoff_factor),
                self.min_speed
            )

            # Insert inter-block delay proportional to congestion severity
            # More congested = longer delay between blocks
            severity = min((rtt_ratio - self.congestion_threshold) / 0.5, 2.0)
            self._inter_block_delay = min(
                self._baseline_rtt * (1 + severity * 2),
                5.0  # cap at 5 seconds
            )

        elif rtt_ratio < self.clear_threshold:
            # CLEAR: RTT near baseline, no congestion
            self._clear_streak += 1
            self._congestion_streak = 0

            if self._clear_streak >= 2:
                # Need 2 consecutive clear readings to ramp
                # Require 2 consecutive clear readings before ramping
                self._state = "ramping"
                self._current_speed = min(
                    int(self._current_speed * self.ramp_factor),
                    max_speed
                )
                # Reduce inter-block delay
                self._inter_block_delay = max(
                    self._inter_block_delay * 0.5,
                    0
                )
        else:
            # IN BETWEEN: hold steady
            self._state = "steady"
            self._clear_streak = 0
            # Don't reset congestion streak — sustained borderline = caution

        # Dynamic block sizing based on throughput
        avg_throughput = statistics.mean(s.throughput for s in recent)
        if avg_throughput > 2_000_000:
            self.block_size = 256 * 1024   # 256 KB for fast links
        elif avg_throughput > 500_000:
            self.block_size = 128 * 1024   # 128 KB standard
        elif avg_throughput > 100_000:
            self.block_size = 64 * 1024    # 64 KB for slow links
        else:
            self.block_size = 32 * 1024    # 32 KB for very slow

    def get_inter_block_delay(self) -> float:
        """
        Get the delay to insert before the next block transfer.
        Primary rate control mechanism — delays between blocks, NOT bandwidth capping.
        """
        with self._lock:
            return self._inter_block_delay

    def get_transfer_config(self):
        """Get boto3 TransferConfig with current adaptive settings."""
        from boto3.s3.transfer import TransferConfig
        speed = self.current_speed

        # Dynamic chunk size based on current speed
        if speed > 2_000_000:
            chunk = 16 * 1024 * 1024    # 16 MB chunks
            concurrency = 4
        elif speed > 1_000_000:
            chunk = 8 * 1024 * 1024     # 8 MB chunks
            concurrency = 3
        elif speed > 500_000:
            chunk = 4 * 1024 * 1024     # 4 MB chunks
            concurrency = 2
        else:
            chunk = 2 * 1024 * 1024     # 2 MB chunks
            concurrency = 1

        return TransferConfig(
            max_bandwidth=speed,
            multipart_chunksize=chunk,
            max_concurrency=concurrency,
            use_threads=True,
        )

    def get_status(self) -> dict:
        """Current controller status for monitoring/logging."""
        with self._lock:
            recent = list(self._samples)[-10:] if self._samples else []
            elapsed_total = time.time() - self._started

            return {
                "speed_mbps": round(self._current_speed / (1024 * 1024), 2),
                "max_mbps": round(self.max_bandwidth / (1024 * 1024), 2),
                "work_rate": self.current_work_rate,
                "state": self._state,
                "baseline_rtt_ms": round(self._baseline_rtt * 1000, 1),
                "current_rtt_ms": round(statistics.median(s.rtt for s in recent) * 1000, 1) if recent else 0,
                "rtt_ratio": round(
                    statistics.median(s.rtt for s in recent) / self._baseline_rtt, 2
                ) if recent and self._baseline_rtt > 0 else 0,
                "inter_block_delay_ms": round(self._inter_block_delay * 1000, 1),
                "block_size_kb": self.block_size // 1024,
                "avg_throughput_mbps": round(
                    statistics.mean(s.throughput for s in recent) / (1024 * 1024), 2
                ) if recent else 0,
                "samples": len(self._samples),
                "total_transferred_mb": round(self._total_bytes / (1024 * 1024), 1),
                "uptime_min": round(elapsed_total / 60, 1),
                "congestion_streak": self._congestion_streak,
            }

    # Backward compatibility aliases
    def report_transfer(self, bytes_transferred: int, elapsed: float, rtt: float = None):
        """Alias for report_block — backward compat with old uploader."""
        self.report_block(bytes_transferred, elapsed)

    def __repr__(self):
        s = self.get_status()
        return (
            f"BW({s['speed_mbps']}MB/s, {s['state']}, "
            f"rtt={s['current_rtt_ms']}ms/{s['baseline_rtt_ms']}ms={s['rtt_ratio']}x, "
            f"delay={s['inter_block_delay_ms']}ms, wr={s['work_rate']:.0%})"
        )
