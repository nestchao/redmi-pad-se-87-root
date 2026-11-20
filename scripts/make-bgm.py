"""Synthesise a 43 s dark-tech score for the CVE-2026-98260 promo.

Design: 120 BPM (0.5 s / beat), A minor. Sparse and low so it supports the typography
instead of competing with it. Every scene cut and every important beat gets a sound
event, because a cut with no sound reads as a glitch.

Output: 16-bit stereo WAV at 44.1 kHz.
"""
import os
import wave

import numpy as np

SR = 44100
DUR = 43.0
N = int(SR * DUR)
T = np.arange(N) / SR

BEAT = 0.5          # 120 BPM
BAR = 4 * BEAT      # 2.0 s

L = np.zeros(N)
R = np.zeros(N)


def place(sig, t0, pan=0.0, gain=1.0):
    """Add a mono signal at time t0 with constant-power pan, -1..1."""
    i0 = int(round(t0 * SR))
    if i0 >= N:
        return
    sig = sig[: N - i0] * gain
    a = (pan + 1) * np.pi / 4
    L[i0:i0 + len(sig)] += sig * np.cos(a)
    R[i0:i0 + len(sig)] += sig * np.sin(a)


def exp_env(n, attack=0.002, decay=0.3):
    a = max(1, int(attack * SR))
    e = np.ones(n)
    e[:a] = np.linspace(0, 1, a)
    d = np.exp(-np.arange(n) / (decay * SR))
    return e * d


def kick(dur=0.42, f0=130.0, f1=42.0, amp=0.55):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = f1 + (f0 - f1) * np.exp(-t / 0.035)
    ph = 2 * np.pi * np.cumsum(f) / SR
    body = np.sin(ph) * exp_env(n, 0.001, 0.16)
    click = np.random.default_rng(1).standard_normal(n) * exp_env(n, 0.0005, 0.006) * 0.12
    return (body + click) * amp


def sub_hit(dur=0.9, freq=41.2, amp=0.42):
    n = int(dur * SR)
    t = np.arange(n) / SR
    sig = np.sin(2 * np.pi * freq * t) * exp_env(n, 0.004, 0.30)
    return sig * amp


def hat(dur=0.06, amp=0.075, seed=2):
    n = int(dur * SR)
    rng = np.random.default_rng(seed)
    x = rng.standard_normal(n)
    x = np.diff(np.concatenate([[0.0], x]))          # cheap high-pass
    return x * exp_env(n, 0.0005, 0.012) * amp


def tick(freq=2400.0, dur=0.05, amp=0.10):
    n = int(dur * SR)
    t = np.arange(n) / SR
    return np.sin(2 * np.pi * freq * t) * exp_env(n, 0.0005, 0.010) * amp


def impact(dur=1.20, amp=0.62):
    n = int(dur * SR)
    t = np.arange(n) / SR
    low = np.sin(2 * np.pi * (34 + 20 * np.exp(-t / 0.25)) * t) * exp_env(n, 0.003, 0.42)
    rng = np.random.default_rng(7)
    nz = rng.standard_normal(n)
    nz = np.diff(np.concatenate([[0.0], nz])) * exp_env(n, 0.001, 0.10) * 0.18
    return (low + nz) * amp


def riser(t0, t1, amp=0.20, seed=11):
    """Noise + rising tone sweep, ending at t1."""
    dur = t1 - t0
    n = int(dur * SR)
    t = np.arange(n) / SR
    p = t / dur
    rng = np.random.default_rng(seed)
    nz = rng.standard_normal(n)
    nz = np.diff(np.concatenate([[0.0], nz]))
    # progressive brightening: mix in the differentiated (brighter) signal
    x = nz * (0.25 + 0.75 * p)
    f = 180.0 * (2 ** (p * 3.4))                     # 180 Hz -> ~1.9 kHz
    tone = np.sin(2 * np.pi * np.cumsum(f) / SR) * 0.45
    shape = p ** 2.2
    sig = (x * 0.7 + tone) * shape
    place(sig, t0, pan=0.0, gain=amp)


def make_pad(notes, t0, t1, amp=0.16, bright=0.0, seed=21):
    """Slow additive pad for the given window."""
    dur = t1 - t0
    n = int(dur * SR)
    t = np.arange(n) / SR
    sig = np.zeros(n)
    for i, f in enumerate(notes):
        det = 1.0 + (i - len(notes) / 2) * 0.0012
        sig += np.sin(2 * np.pi * f * det * t + i * 0.7) * (1.0 / (1 + i * 0.35))
        if bright > 0:
            sig += np.sin(2 * np.pi * f * 4 * t + i) * bright / (1 + i * 0.6)
    lfo = 0.72 + 0.28 * np.sin(2 * np.pi * 0.09 * t)
    a = int(0.9 * SR)
    r = int(1.8 * SR)
    e = np.ones(n)
    if a < n:
        e[:a] = np.linspace(0, 1, a) ** 1.5
    if r < n:
        e[-r:] = np.linspace(1, 0, r) ** 1.2
    sig = sig * lfo * e * amp
    place(sig, t0, pan=0.0)


# ----------------------------------------------------------------------------
# Harmony (A minor), low register
A2, C3, E3, A3 = 110.0, 130.81, 164.81, 220.0
CHORD = [A2, C3, E3, A3]
CHORD_HI = [A2, C3, E3, A3, 329.63, 440.0]

# --- continuous bed ---------------------------------------------------------
make_pad(CHORD, 0.0, 11.2, amp=0.155)
make_pad(CHORD, 11.0, 20.0, amp=0.145)
make_pad(CHORD, 19.6, 26.8, amp=0.150)
make_pad(CHORD, 26.4, 34.0, amp=0.150)
make_pad(CHORD_HI, 33.5, 40.2, amp=0.150, bright=0.10)
make_pad(CHORD_HI, 39.6, 43.0, amp=0.135, bright=0.06)

# sustained sub
sub = np.sin(2 * np.pi * 55.0 * T) * (0.055 + 0.015 * np.sin(2 * np.pi * 0.13 * T))
fade = np.ones(N)
fade[: int(1.2 * SR)] = np.linspace(0, 1, int(1.2 * SR))
fade[-int(2.2 * SR):] = np.linspace(1, 0, int(2.2 * SR))
L += sub * fade
R += sub * fade

# --- percussion grid --------------------------------------------------------
rng = np.random.default_rng(99)

# 0.0-4.65  intro: kick on the bar only
for b in np.arange(0.0, 4.65, BAR):
    place(kick(), b, pan=0.0, gain=0.90)

# stamp under "FULL ROOT"
place(kick(dur=0.6, amp=0.62), 0.86, pan=0.0)
place(sub_hit(dur=1.0, amp=0.40), 0.86)

# 4.65-11.0  failure: kick 1 & 3, hats from 6.0
for b in np.arange(4.8, 11.0, BAR):
    place(kick(), b, pan=0.0, gain=0.88)
    place(kick(dur=0.34, amp=0.40), b + 2 * BEAT, pan=0.0, gain=0.80)
for h in np.arange(6.0, 11.0, BEAT):
    place(hat(seed=int(h * 7) % 50), h, pan=0.25, gain=0.9)
place(kick(dur=0.5, amp=0.58), 6.06, pan=0.0)   # "base calibration failed"

# riser into the comparison scene
riser(8.6, 11.0, amp=0.24)
place(impact(amp=0.55), 11.0)

# 11.0-19.6  the comparison + reveal: no hats, space to read
for b in np.arange(11.0, 19.4, BAR):
    place(kick(), b, pan=0.0, gain=0.82)
place(tick(1800), 11.34, pan=-0.2)              # runtime value arrives
place(tick(1500, amp=0.09), 12.50, pan=-0.1)    # digits marked
place(sub_hit(dur=0.7, freq=49.0, amp=0.34), 12.76)  # unequal
place(kick(dur=0.30, amp=0.34), 12.76)

riser(13.2, 14.94, amp=0.26)                    # build to the reveal
place(impact(dur=1.5, amp=0.66), 14.94)         # slide & 0x1fffff = 0x80000
place(sub_hit(dur=1.4, freq=36.7, amp=0.40), 14.94)
place(tick(2600, amp=0.08), 15.52)

# 19.6-26.5  the fix
riser(18.2, 19.6, amp=0.20)
place(impact(dur=1.0, amp=0.50), 19.6)
for b in np.arange(19.8, 26.4, BAR):
    place(kick(), b, pan=0.0, gain=0.86)
    place(kick(dur=0.32, amp=0.36), b + 2 * BEAT, pan=0.0, gain=0.75)
for h in np.arange(20.0, 26.4, BEAT):
    place(hat(seed=int(h * 11) % 60, amp=0.055), h, pan=0.30, gain=0.85)
# the counter rolling and the winner lighting up
place(tick(900, amp=0.07), 20.70, pan=0.0)
place(tick(1400, amp=0.09), 21.30, pan=0.0)
place(tick(2100, amp=0.12), 21.70, pan=0.0)
place(kick(dur=0.28, amp=0.30), 21.70, pan=0.0)
place(tick(2600, amp=0.09), 22.46)               # the log line

# 26.5-33.55  the chain
riser(25.1, 26.5, amp=0.20)
place(impact(dur=1.0, amp=0.50), 26.5)
for b in np.arange(26.6, 33.4, BAR):
    place(kick(), b, pan=0.0, gain=0.86)
    place(kick(dur=0.32, amp=0.36), b + 2 * BEAT, pan=0.0, gain=0.75)
for h in np.arange(26.8, 33.4, BEAT):
    place(hat(seed=int(h * 13) % 70, amp=0.05), h, pan=0.30, gain=0.85)
# a rising ping as each stage lands and each one is confirmed
for i, tt in enumerate([26.84, 27.34, 27.84]):
    place(tick(1100 + i * 260, amp=0.09), tt, pan=-0.35 + i * 0.35)
for i, tt in enumerate([28.22, 28.46, 28.70]):
    place(tick(1500 + i * 330, amp=0.085), tt, pan=-0.35 + i * 0.35)
place(sub_hit(dur=0.8, freq=61.7, amp=0.26), 29.10)   # KernelSU loaded

# big build into the result
riser(30.4, 33.55, amp=0.30)
place(impact(dur=1.8, amp=0.70), 33.55)
place(sub_hit(dur=1.8, freq=32.7, amp=0.44), 33.55)

# 33.55-39.7  the result: full beat
for b in np.arange(33.6, 39.6, BAR):
    place(kick(), b, pan=0.0, gain=0.92)
    place(kick(dur=0.32, amp=0.40), b + 2 * BEAT, pan=0.0, gain=0.80)
for h in np.arange(33.7, 39.6, BEAT / 2):
    place(hat(seed=int(h * 17) % 80, amp=0.045), h, pan=0.35, gain=0.8)
for i, tt in enumerate([34.07, 34.39, 34.71]):
    place(tick(1600 + i * 300, amp=0.075), tt, pan=0.0)
place(sub_hit(dur=0.9, freq=49.0, amp=0.24), 34.92)   # "0 partition writes"

# 39.7-43.0  coda
place(impact(dur=1.4, amp=0.48), 39.70)
for b in np.arange(39.7, 41.8, BAR):
    place(kick(dur=0.5, amp=0.38), b, pan=0.0, gain=0.7)

# ----------------------------------------------------------------------------
# Master: gentle low shelf cut, soft clip, normalise, final fade
def onepole_lp(x, cutoff):
    a = np.exp(-2 * np.pi * cutoff / SR)
    y = np.empty_like(x)
    acc = 0.0
    for i in range(len(x)):
        acc = a * acc + (1 - a) * x[i]
        y[i] = acc
    return y


# cheap de-rumble by removing the very low DC drift on the stereo bus
for ch in (L, R):
    ch -= np.convolve(ch, np.ones(2048) / 2048, mode="same") * 0.35

mix = np.stack([L, R], axis=1)

# soft clip (tanh) keeps transients punchy without hard edges
drive = 1.15
mix = np.tanh(mix * drive) / np.tanh(drive)

# final fades
fi = int(1.0 * SR)
fo = int(2.0 * SR)
mix[:fi] *= np.linspace(0, 1, fi)[:, None] ** 1.2
mix[-fo:] *= np.linspace(1, 0, fo)[:, None] ** 1.6

peak = np.max(np.abs(mix))
target = 10 ** (-1.0 / 20)          # -1 dBFS
mix = mix / peak * target

out_dir = r"D:\Projects\Video"
os.makedirs(out_dir, exist_ok=True)
out = os.path.join(out_dir, "bgm-promo.wav")
pcm = (mix * 32767).astype(np.int16)
with wave.open(out, "wb") as w:
    w.setnchannels(2)
    w.setsampwidth(2)
    w.setframerate(SR)
    w.writeframes(pcm.tobytes())

rms = np.sqrt(np.mean(mix ** 2))
print("wrote %s" % out)
print("duration %.2fs  peak %.1f dBFS  rms %.1f dBFS  size %.1f MB"
      % (len(mix) / SR, 20 * np.log10(peak / peak), 20 * np.log10(rms),
         os.path.getsize(out) / 1e6))
