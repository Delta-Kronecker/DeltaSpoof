# DeltaSpoof

> **Cross-platform DPI bypass proxy** — forked from [nullroute1970/ZeroDPI](https://github.com/nullroute1970/ZeroDPI)

DeltaSpoof sits between your **upstream VPN app** (xray-core, sing-box, v2ray, etc.) and the internet, transparently evading **Deep Packet Inspection (DPI)** that would otherwise block or throttle your VPN traffic.

It works on **Windows**, **Linux**, and **rooted Android/Termux**.

---

## What Changed from ZeroDPI

This fork adds the **`find_ip` mode** — a new operating mode that helps you find the best IP from a CIDR range for a specific CDN domain.

### New Features

| Feature | Description |
|---------|-------------|
| **`find_ip` mode** | Full workflow: SNI scan → select domain → select IP range → test IPs → live proxy with dynamic pool |
| **Live IP dashboard** | Real-time table showing ↑/Cycle, ↓/Cycle, Total, Conns, Cycles, Duration for each active IP |
| **Dynamic IP pool** | IPs with 0 total bytes are automatically removed; new IPs are scanned and added in real-time |
| **Per-cycle byte tracking** | Upload/download bytes are tracked per evaluation cycle and reset each cycle |
| **IP selection picker** | Press `s` to stop and pick from all IPs ever used, sorted by total bytes |
| **Domain change** | Press `d` to change the domain without restarting |
| **IP range change** | Press `r` to change the IP range during scanning |
| **Special domain priority** | `www.hcaptcha.com` always ranks first in SNI scan results (shown in magenta) |
| **Scan stats in header** | Shows scanned count, successful count, and removed count |
| **Auto-start** | Automatically starts when 2x MAX_IP candidates are found |
| **IP scan results saved** | Results are saved to `find-ip-results.json` |
| **Removed unused features** | Removed star markers and separator lines for special domains |

### Removed from ZeroDPI

- Star markers (`★`) and separator lines for special domain display
- `proxy_scan` mode (not needed for this use case)
- `ip_bypass_plus` mode (not needed for this use case)

### Configuration Changes

- Default port changed from `44444` to `40443`
- New config fields:
  - `MAX_IP = 10` — Maximum concurrent IPs in the pool
  - `IP_TEST_TIMEOUT_SECS = 10` — Seconds per evaluation cycle
  - `FIND_IP_DROP_COUNT = 5` — Number of lowest-total IPs to remove when all have bytes
  - `FIND_IP_MIN_BYTES = 1024` — Minimum bytes to consider an IP alive

---

## How It Works

1. **SNI Scan** — Scans candidate hostnames from `sni_list.txt`, ranks by score (TCP latency, TLS, TTFB, speed)
2. **Select Domain** — User picks a domain (or auto-selects the best)
3. **Select IP Range** — User picks a CIDR range from `ip_list.txt`
4. **IP Scan** — Tests all IPs in the range against the selected domain
5. **Live Proxy** — Starts with top-scored IPs, distributes VPN traffic across them
6. **Dynamic Pool** — Every `IP_TEST_TIMEOUT_SECS` seconds:
   - Removes IPs with 0 total bytes
   - When all have bytes, removes the lowest-total IPs
   - Scans and adds replacement IPs
7. **Pick IP** — Press `s` to stop and select the best IP
8. **Continue** — Press `p` to pick a different IP from the full history

---

## Quick Start

1. **Edit `config.toml`** — Set `MODE = "find_ip"` and configure `MAX_IP`
2. **Fill `sni_list.txt`** with CDN hostnames
3. **Fill `ip_list.txt`** with CIDR ranges (e.g., Cloudflare ranges)
4. **Run:**
```powershell
# Windows (Admin)
.\deltaspoof.exe --config .\config.toml

# Linux
sudo ./deltaspoof --config ./config.toml
```
5. **Select domain** → **Select IP range** → **Watch live dashboard**
6. **Press `s`** when you see good IPs → **Pick the best one**

---

## Dashboard Controls

| Key | Action |
|-----|--------|
| `s` | Stop scanning and pick best IP |
| `d` | Change domain (back to SNI scan) |
| `r` | Change IP range (back to CIDR selection) |
| `p` | Pick a different IP (when in Fixed mode) |
| `q` / `Esc` | Quit |

---

## Building from Source

Requires **Rust 1.75+**.

```bash
# Build
cargo build --release

# Or with Python helper
python build.py --platform linux|windows|termux
```

---

## Credits

- Original project: [nullroute1970/ZeroDPI](https://github.com/nullroute1970/ZeroDPI)
- DPI bypass research: [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)

## License

MIT — see [LICENSE](LICENSE).
