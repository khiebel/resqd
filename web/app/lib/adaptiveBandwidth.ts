/**
 * Adaptive bandwidth controller — LEDBAT-style polite-lane throttling.
 *
 * Ports the `/Users/khiebel/hiebel/shared/adaptive_bandwidth.py`
 * controller (Kevin's 3090 uploader) into the browser so RESQD's
 * streaming uploads can voluntarily back off when the home pipe gets
 * squeezed. Same thresholds, same state machine, same behavior on
 * synthetic RTT traces.
 *
 * ## How it works
 *
 * Every time a block (e.g. an S3 multipart part) finishes, the caller
 * reports the wall-clock elapsed time and the byte count via
 * `reportBlock()`. The controller computes a normalized RTT per block
 * (elapsed × block_size / bytes), tracks a rolling median, and compares
 * it to a baseline established from the minimum RTT of the first few
 * samples. When the ratio exceeds the congestion threshold, it inserts
 * an inter-block delay that the upload loop honors via `setTimeout`.
 * When the ratio is clear for two consecutive blocks, it ramps the
 * allowed speed back up.
 *
 * Nothing in this file touches the network. It's a pure state machine
 * that the streaming uploader feeds and queries.
 */

export type BandwidthState = "calibrating" | "ramping" | "steady" | "backing_off";

export interface BandwidthControllerOptions {
  /** Pipe ceiling in bytes/sec. Default 10 MB/s — matches Kevin's home upload. */
  maxBandwidthBps?: number;
  /** Hard floor in bytes/sec below which we won't back off further. */
  minSpeedBps?: number;
  /** Target utilization as a fraction of max (default 0.75 = 75%). */
  workRate?: number;
  /** RTT ratio above which we consider the path congested. */
  congestionThreshold?: number;
  /** RTT ratio below which we consider the path clear. */
  clearThreshold?: number;
  /** Multiplier applied to current speed on each clear reading. */
  rampFactor?: number;
  /** Multiplier applied to current speed on congestion. */
  backoffFactor?: number;
  /** Baseline block size in bytes for RTT normalization. */
  baseBlockSize?: number;
}

interface BlockSample {
  timestampMs: number;
  blockSize: number;
  elapsedMs: number;
  rttMs: number;
  throughputBps: number;
  delayAppliedMs: number;
}

export class AdaptiveBandwidthController {
  private readonly maxBandwidthBps: number;
  private readonly minSpeedBps: number;
  private readonly workRate: number;
  private readonly congestionThreshold: number;
  private readonly clearThreshold: number;
  private readonly rampFactor: number;
  private readonly backoffFactor: number;

  private blockSize: number;
  private state: BandwidthState = "calibrating";
  private baselineRttMs = 0;
  private currentSpeedBps: number;
  private samples: BlockSample[] = [];
  private interBlockDelayMs = 0;
  private clearStreak = 0;
  private congestionStreak = 0;
  private totalBytes = 0;
  private totalTimeMs = 0;

  constructor(opts: BandwidthControllerOptions = {}) {
    this.maxBandwidthBps = opts.maxBandwidthBps ?? 10 * 1024 * 1024;
    this.minSpeedBps = opts.minSpeedBps ?? 64 * 1024;
    this.workRate = opts.workRate ?? 0.75;
    this.congestionThreshold = opts.congestionThreshold ?? 1.4;
    this.clearThreshold = opts.clearThreshold ?? 1.15;
    this.rampFactor = opts.rampFactor ?? 1.08;
    this.backoffFactor = opts.backoffFactor ?? 0.5;
    this.blockSize = opts.baseBlockSize ?? 1 * 1024 * 1024;
    this.currentSpeedBps = Math.floor(this.maxBandwidthBps * this.workRate);
  }

  /**
   * Report a completed transfer block. `bytes` is how much was sent,
   * `elapsedMs` is the wall-clock for the whole transfer (network +
   * any CPU work the caller wants to reflect in the measurement).
   */
  reportBlock(bytes: number, elapsedMs: number): void {
    if (bytes <= 0 || elapsedMs <= 0) return;

    const throughputBps = bytes / (elapsedMs / 1000);
    // Normalize this block's elapsed time to a common block size so
    // samples are comparable even when part sizes vary.
    const normalizedRttMs = elapsedMs * (this.blockSize / bytes);

    this.samples.push({
      timestampMs: Date.now(),
      blockSize: bytes,
      elapsedMs,
      rttMs: normalizedRttMs,
      throughputBps,
      delayAppliedMs: this.interBlockDelayMs,
    });
    // Keep only the most recent 20 samples — matches the Python
    // controller's rolling window behavior.
    if (this.samples.length > 20) {
      this.samples.splice(0, this.samples.length - 20);
    }

    this.totalBytes += bytes;
    this.totalTimeMs += elapsedMs;

    // Baseline calibration: once we have 5 samples, take the min as
    // the "no-congestion" RTT and move to ramping.
    if (this.state === "calibrating" && this.samples.length >= 5) {
      this.baselineRttMs = Math.min(...this.samples.map((s) => s.rttMs));
      this.state = "ramping";
    }

    // Only adjust once we have enough samples to compute a stable median.
    if (this.samples.length >= 3) this.adjust();
  }

  /**
   * How long the caller should sleep between blocks. Honor this via
   * `await new Promise(r => setTimeout(r, ms))` in the upload loop.
   */
  getInterBlockDelayMs(): number {
    return this.interBlockDelayMs;
  }

  /** Current speed ceiling in bytes/sec. Advisory; S3 multipart does the real work. */
  getCurrentSpeedBps(): number {
    return this.currentSpeedBps;
  }

  /** Current lifecycle state. Useful for UX badges. */
  getState(): BandwidthState {
    return this.state;
  }

  /** Averaged throughput across the whole session, bytes/sec. */
  getOverallThroughputBps(): number {
    if (this.totalTimeMs <= 0) return 0;
    return this.totalBytes / (this.totalTimeMs / 1000);
  }

  // ── Internals ────────────────────────────────────────────────────

  private adjust(): void {
    const recent = this.samples.slice(-10);
    if (recent.length === 0 || this.baselineRttMs <= 0) return;

    const currentRttMs = median(recent.map((s) => s.rttMs));
    const rttRatio = currentRttMs / this.baselineRttMs;
    const maxSpeedBps = Math.floor(this.maxBandwidthBps * this.workRate);

    if (rttRatio > this.congestionThreshold) {
      // Congested: halve speed and insert proportional inter-block delay.
      this.congestionStreak += 1;
      this.clearStreak = 0;
      this.state = "backing_off";
      this.currentSpeedBps = Math.max(
        Math.floor(this.currentSpeedBps * this.backoffFactor),
        this.minSpeedBps,
      );
      const severity = Math.min((rttRatio - this.congestionThreshold) / 0.5, 2.0);
      this.interBlockDelayMs = Math.min(
        this.baselineRttMs * (1 + severity * 2),
        5000,
      );
    } else if (rttRatio < this.clearThreshold) {
      // Clear path: need TWO consecutive clears before ramping,
      // matching the Python controller's "2 clear readings before
      // speeding up" rule. Prevents thrashing on transient lulls.
      this.clearStreak += 1;
      this.congestionStreak = 0;
      if (this.clearStreak >= 2) {
        this.state = "ramping";
        this.currentSpeedBps = Math.min(
          Math.floor(this.currentSpeedBps * this.rampFactor),
          maxSpeedBps,
        );
        this.interBlockDelayMs = Math.max(this.interBlockDelayMs * 0.5, 0);
      }
    } else {
      // Borderline: hold steady. Don't reset congestion streak —
      // sustained borderline RTT counts as caution, matching Python.
      this.state = "steady";
      this.clearStreak = 0;
    }
  }
}

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const sorted = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}
