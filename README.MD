# Cross-platform Metrics HTTP API (C++)

A lightweight cross-platform HTTP API server written in modern C++ 20 to expose system metrics (CPU, memory, network, disk IOPS) on Linux and Windows.

## Features
- Exposes a simple JSON API at `/metrics` over HTTP.
- Reports:
  - **CPU usage %**
  - **Memory total, available, used %**
  - **Network throughput** (bytes per second, total counters)
  - **Disk IOPS** (reads/sec, writes/sec, total)
- Cross-platform:
  - Linux: uses `/proc/stat`, `/proc/meminfo`, `/proc/net/dev`, `/proc/diskstats`
  - Windows: uses `GetSystemTimes`, `GlobalMemoryStatusEx`, IP Helper API, PDH counters
- Built-in minimal HTTP server (no external dependencies)
- Portable build via **CMake**
- Systemd service unit for Linux deployment

## Build Instructions

### Requirements
- C++20 compiler (g++ ≥ 7, clang++ ≥ 6, MSVC ≥ 2019)
- CMake ≥ 3.12

### Linux (g++/clang++)
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build
```

### Windows (MSVC)
```bat
cmake -S . -B build
cmake --build build --config Release
```

On Windows, links against: `Ws2_32`, `Iphlpapi`, `Pdh`.

## Usage

Run the server (defaults to port 8080):
```bash
./metrics_server --port 8080
```

Access metrics:
```bash
curl http://localhost:8080/metrics
```

Example response:
```json
{
  "cpu": { "percent": 12.34 },
  "memory": {
    "total_bytes": 33554432000,
    "available_bytes": 1234567890,
    "used_percent": 63.21
  },
  "network": {
    "rx_bytes_total": 9876543210,
    "tx_bytes_total": 123456789,
    "rx_bytes_per_sec": 10240.00,
    "tx_bytes_per_sec": 20480.00
  },
  "disk": {
    "reads_per_sec": 120.00,
    "writes_per_sec": 80.00,
    "total_iops": 200.00
  }
}
```

## Installation as a Systemd Service (Linux)

A systemd unit file is provided at `packaging/metrics-server.service`.

### Steps
```bash
# Create dedicated system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin metrics

# Edit default configuration (port, extra args)
sudoedit /etc/default/metrics-server

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable --now metrics-server

# Check status
systemctl status metrics-server
```

Environment variables:
- `PORT`: Listening port (default 8080)
- `EXTRA_ARGS`: Extra flags passed to the binary

## Security Notes
- By default, CORS is enabled (`Access-Control-Allow-Origin: *`).
- The service is hardened with systemd options (read-only system, private tmp).
- Consider running behind a reverse proxy if exposed externally.

## License
MIT License. Feel free to use, modify, and distribute.
