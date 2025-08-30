#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Pdh.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

// ------------------ Utilities ------------------
static uint16_t parse_port(int argc, char** argv, uint16_t def = 8080) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "-p" || a == "--port") && i + 1 < argc) {
            int v = std::stoi(argv[++i]);
            if (v > 0 && v < 65536) return static_cast<uint16_t>(v);
        } else if (a.rfind("--port=", 0) == 0) {
            int v = std::stoi(a.substr(8));
            if (v > 0 && v < 65536) return static_cast<uint16_t>(v);
        }
    }
    return def;
}

static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '\\': o << "\\\\"; break;
            case '"': o << "\\\""; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

// ------------------ Metrics state ------------------
struct MetricsState {
    // CPU
    std::mutex mtx;
    double cpu_percent = 0.0;

    // Memory
    uint64_t mem_total = 0;      // bytes
    uint64_t mem_available = 0;  // bytes

    // Network total (across non-loopback interfaces)
    uint64_t net_rx_bytes_total = 0; // cumulative
    uint64_t net_tx_bytes_total = 0; // cumulative
    double net_rx_bytes_per_sec = 0.0; // rate
    double net_tx_bytes_per_sec = 0.0; // rate

    // Disk IOPS (total reads/writes per second)
    double disk_reads_per_sec = 0.0;
    double disk_writes_per_sec = 0.0;
};

static MetricsState g_metrics;
static std::atomic<bool> g_running{true};

// ------------------ Platform-specific collectors ------------------
#ifdef _WIN32

static inline unsigned long long filetime_to_ull(const FILETIME& ft) {
    ULARGE_INTEGER li; li.LowPart = ft.dwLowDateTime; li.HighPart = ft.dwHighDateTime; return li.QuadPart;
}

struct CpuSnapshotWin { unsigned long long idle=0, kernel=0, user=0; };

static CpuSnapshotWin read_cpu_snapshot_win() {
    FILETIME idleFT, kernelFT, userFT;
    CpuSnapshotWin s{};
    if (GetSystemTimes(&idleFT, &kernelFT, &userFT)) {
        s.idle = filetime_to_ull(idleFT);
        s.kernel = filetime_to_ull(kernelFT);
        s.user = filetime_to_ull(userFT);
    }
    return s;
}

static void read_memory_win(uint64_t& total, uint64_t& available) {
    MEMORYSTATUSEX st; st.dwLength = sizeof(st);
    if (GlobalMemoryStatusEx(&st)) {
        total = st.ullTotalPhys;
        available = st.ullAvailPhys;
    }
}

static void read_network_counters_win(uint64_t& in_octets, uint64_t& out_octets) {
    in_octets = out_octets = 0;
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) == NO_ERROR && table) {
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const MIB_IF_ROW2& r = table->Table[i];
            if (r.InterfaceAndOperStatusFlags.FilterInterface || r.MediaConnectState != MediaConnectStateConnected) continue;
            if (r.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            in_octets += (uint64_t)r.InOctets;
            out_octets += (uint64_t)r.OutOctets;
        }
        FreeMibTable(table);
    }
}

// Disk IOPS via PDH PhysicalDisk(_Total) counters
struct PdhState {
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER reads = nullptr;
    PDH_HCOUNTER writes = nullptr;
    bool ok = false;
};

static PdhState init_pdh() {
    PdhState s{};
    if (PdhOpenQuery(NULL, 0, &s.query) != ERROR_SUCCESS) return s;
    // Use English counter names to avoid locale issues
    if (PdhAddEnglishCounter(s.query, "\\PhysicalDisk(_Total)\\Disk Reads/sec", 0, &s.reads) != ERROR_SUCCESS) return s;
    if (PdhAddEnglishCounter(s.query, "\\PhysicalDisk(_Total)\\Disk Writes/sec", 0, &s.writes) != ERROR_SUCCESS) return s;
    if (PdhCollectQueryData(s.query) != ERROR_SUCCESS) return s; // prime
    s.ok = true;
    return s;
}

static void get_pdh_rates(PdhState& s, double& rps, double& wps) {
    rps = wps = 0.0;
    if (!s.ok) return;
    if (PdhCollectQueryData(s.query) != ERROR_SUCCESS) return;
    PDH_FMT_COUNTERVALUE v{};
    DWORD type = 0;
    if (PdhGetFormattedCounterValue(s.reads, PDH_FMT_DOUBLE, &type, &v) == ERROR_SUCCESS) rps = v.doubleValue;
    if (PdhGetFormattedCounterValue(s.writes, PDH_FMT_DOUBLE, &type, &v) == ERROR_SUCCESS) wps = v.doubleValue;
}

static void sampler_win() {
    CpuSnapshotWin prev = read_cpu_snapshot_win();
    uint64_t prev_in_octets=0, prev_out_octets=0; read_network_counters_win(prev_in_octets, prev_out_octets);
    PdhState pdh = init_pdh();

    while (g_running.load()) {
        std::this_thread::sleep_for(1s);
        // CPU
        CpuSnapshotWin cur = read_cpu_snapshot_win();
        unsigned long long idle = (cur.idle - prev.idle);
        unsigned long long kernel = (cur.kernel - prev.kernel);
        unsigned long long user = (cur.user - prev.user);
        unsigned long long total = kernel + user;
        double cpu = 0.0;
        if (total > 0) cpu = (1.0 - (double)idle / (double)total) * 100.0;
        prev = cur;

        // Memory
        uint64_t mem_total=0, mem_avail=0; read_memory_win(mem_total, mem_avail);

        // Network
        uint64_t in_oct=0, out_oct=0; read_network_counters_win(in_oct, out_oct);
        double rx_ps = 0.0, tx_ps = 0.0;
        if (in_oct >= prev_in_octets) rx_ps = (double)(in_oct - prev_in_octets);
        if (out_oct >= prev_out_octets) tx_ps = (double)(out_oct - prev_out_octets);
        prev_in_octets = in_oct; prev_out_octets = out_oct;

        // Disk IOPS via PDH
        double rps=0.0, wps=0.0; get_pdh_rates(pdh, rps, wps);

        // Publish
        {
            std::lock_guard<std::mutex> lk(g_metrics.mtx);
            g_metrics.cpu_percent = cpu;
            g_metrics.mem_total = mem_total;
            g_metrics.mem_available = mem_avail;
            g_metrics.net_rx_bytes_total = in_oct;
            g_metrics.net_tx_bytes_total = out_oct;
            g_metrics.net_rx_bytes_per_sec = rx_ps;
            g_metrics.net_tx_bytes_per_sec = tx_ps;
            g_metrics.disk_reads_per_sec = rps;
            g_metrics.disk_writes_per_sec = wps;
        }
    }
}

#else // __linux__ and other POSIX

static bool read_first_line(const std::string& path, std::string& out) {
    std::ifstream f(path); if (!f) return false; std::getline(f, out); return !out.empty();
}

struct CpuSnapshotLinux { unsigned long long idle=0, total=0; };

static CpuSnapshotLinux read_cpu_snapshot_linux() {
    std::string line; CpuSnapshotLinux s{};
    if (!read_first_line("/proc/stat", line)) return s;
    std::istringstream iss(line);
    std::string cpu; iss >> cpu; // "cpu"
    unsigned long long user=0,nice=0,system=0,idle=0,iowait=0,irq=0,softirq=0,steal=0,guest=0,guest_nice=0;
    iss >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;
    unsigned long long idle_all = idle + iowait;
    unsigned long long non_idle = user + nice + system + irq + softirq + steal;
    s.total = idle_all + non_idle;
    s.idle = idle_all;
    return s;
}

static void read_memory_linux(uint64_t& total, uint64_t& available) {
    total = available = 0;
    std::ifstream f("/proc/meminfo");
    std::string key; uint64_t val; std::string unit;
    while (f >> key >> val >> unit) {
        if (key == "MemTotal:") total = val * 1024ull;
        else if (key == "MemAvailable:") { available = val * 1024ull; }
        if (total && available) break;
    }
}

struct NetSnapshotLinux { uint64_t rx=0, tx=0; };

static NetSnapshotLinux read_net_snapshot_linux() {
    NetSnapshotLinux s{};
    std::ifstream f("/proc/net/dev");
    std::string line;
    // skip headers (2 lines)
    std::getline(f, line); std::getline(f, line);
    while (std::getline(f, line)) {
        // format: iface: bytes packets errs drop fifo frame compressed multicast ... | transmit ...
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string ifname = line.substr(0, colon);
        // trim spaces
        size_t start = ifname.find_first_not_of(' ');
        size_t end = ifname.find_last_not_of(' ');
        ifname = (start == std::string::npos) ? "" : ifname.substr(start, end - start + 1);
        if (ifname == "lo" || ifname.rfind("docker",0)==0 || ifname.rfind("veth",0)==0) continue;
        std::istringstream data(line.substr(colon+1));
        unsigned long long rx_bytes=0, rx_packets, rx_errs, rx_drop, rx_fifo, rx_frame, rx_comp, rx_mcast;
        unsigned long long tx_bytes=0, tx_packets, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_comp;
        data >> rx_bytes >> rx_packets >> rx_errs >> rx_drop >> rx_fifo >> rx_frame >> rx_comp >> rx_mcast
             >> tx_bytes >> tx_packets >> tx_errs >> tx_drop >> tx_fifo >> tx_colls >> tx_carrier >> tx_comp;
        s.rx += rx_bytes; s.tx += tx_bytes;
    }
    return s;
}

struct DiskSnapshotLinux { uint64_t reads=0, writes=0; };
static bool is_counted_disk(const std::string& name) {
    if (name.rfind("loop",0)==0 || name.rfind("ram",0)==0 || name.rfind("fd",0)==0) return false;
    if (name.rfind("dm-",0)==0 || name.rfind("md",0)==0 || name.rfind("sr",0)==0 || name.rfind("zd",0)==0) return false;
    // exclude partitions for sd/hd/vd/mmcblk: trailing digits => partition; for nvme, partitions contain 'p'
    bool has_digit_end = !name.empty() && std::isdigit((unsigned char)name.back());
    bool is_nvme = name.rfind("nvme",0)==0;
    if (is_nvme) {
        if (name.find('p') != std::string::npos) return false; // partition like nvme0n1p1
        return true; // count e.g., nvme0n1
    }
    return !has_digit_end; // count e.g., sda, vda, mmcblk0 (oops ends with digit) => special-case mmcblk
}

static DiskSnapshotLinux read_disk_snapshot_linux() {
    DiskSnapshotLinux s{};
    std::ifstream f("/proc/diskstats");
    std::string dev;
    while (f) {
        std::string line; if (!std::getline(f, line)) break; if (line.empty()) continue;
        std::istringstream iss(line);
        int major=0, minor=0; std::string name; unsigned long long stats[11]{};
        // fields per docs: major minor name reads_completed reads_merged sectors_read ms_reading writes_completed writes_merged sectors_written ms_writing ios_in_progress ms_doing_io weighted_ms_doing_io
        if (!(iss >> major >> minor >> name)) continue;
        for (int i=0;i<11 && iss; ++i) iss >> stats[i];
        if (!is_counted_disk(name)) {
            // special-case mmcblk: treat base device like mmcblk0 (ends with digit) as whole; partitions are mmcblk0p1
            if (name.rfind("mmcblk",0)==0) {
                if (name.find('p') != std::string::npos) continue; // partition, skip
            } else {
                continue;
            }
        }
        uint64_t reads_completed = stats[0]; // reads_completed
        uint64_t writes_completed = stats[4]; // writes_completed (5th after name)
        s.reads += reads_completed;
        s.writes += writes_completed;
    }
    return s;
}

static void sampler_linux() {
    CpuSnapshotLinux prev_cpu = read_cpu_snapshot_linux();
    NetSnapshotLinux prev_net = read_net_snapshot_linux();
    DiskSnapshotLinux prev_disk = read_disk_snapshot_linux();

    while (g_running.load()) {
        std::this_thread::sleep_for(1s);
        // CPU
        CpuSnapshotLinux cur_cpu = read_cpu_snapshot_linux();
        unsigned long long totald = (cur_cpu.total - prev_cpu.total);
        unsigned long long idled  = (cur_cpu.idle  - prev_cpu.idle);
        double cpu = (totald > 0) ? (1.0 - (double)idled / (double)totald) * 100.0 : 0.0;
        prev_cpu = cur_cpu;

        // Memory
        uint64_t mem_total=0, mem_avail=0; read_memory_linux(mem_total, mem_avail);

        // Network
        NetSnapshotLinux cur_net = read_net_snapshot_linux();
        double rx_ps = 0.0, tx_ps = 0.0;
        if (cur_net.rx >= prev_net.rx) rx_ps = (double)(cur_net.rx - prev_net.rx);
        if (cur_net.tx >= prev_net.tx) tx_ps = (double)(cur_net.tx - prev_net.tx);

        // Disk IOPS
        DiskSnapshotLinux cur_disk = read_disk_snapshot_linux();
        double rps = 0.0, wps = 0.0;
        if (cur_disk.reads >= prev_disk.reads) rps = (double)(cur_disk.reads - prev_disk.reads);
        if (cur_disk.writes >= prev_disk.writes) wps = (double)(cur_disk.writes - prev_disk.writes);

        prev_net = cur_net; prev_disk = cur_disk;

        // Publish
        {
            std::lock_guard<std::mutex> lk(g_metrics.mtx);
            g_metrics.cpu_percent = cpu;
            g_metrics.mem_total = mem_total;
            g_metrics.mem_available = mem_avail;
            g_metrics.net_rx_bytes_total = cur_net.rx;
            g_metrics.net_tx_bytes_total = cur_net.tx;
            g_metrics.net_rx_bytes_per_sec = rx_ps;
            g_metrics.net_tx_bytes_per_sec = tx_ps;
            g_metrics.disk_reads_per_sec = rps;
            g_metrics.disk_writes_per_sec = wps;
        }
    }
}

#endif

// ------------------ Minimal HTTP server ------------------

struct HttpServer {
#ifdef _WIN32
    SOCKET listen_fd = INVALID_SOCKET;
#else
    int listen_fd = -1;
#endif
    uint16_t port = 8080;

    bool start(uint16_t p) {
        port = p;
#ifdef _WIN32
        WSADATA wsaData; if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) { std::cerr << "WSAStartup failed\n"; return false; }
#endif
        listen_fd = (decltype(listen_fd))socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
        if (listen_fd == INVALID_SOCKET) { std::cerr << "socket() failed\n"; return false; }
#else
        if (listen_fd < 0) { perror("socket"); return false; }
#endif
        int opt = 1;
#ifdef _WIN32
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(port);
        if (
#ifdef _WIN32
            bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR
#else
            bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0
#endif
        ) {
#ifdef _WIN32
            std::cerr << "bind() failed: " << WSAGetLastError() << "\n";
#else
            perror("bind");
#endif
            return false;
        }
        if (
#ifdef _WIN32
            listen(listen_fd, SOMAXCONN) == SOCKET_ERROR
#else
            listen(listen_fd, 16) < 0
#endif
        ) {
#ifdef _WIN32
            std::cerr << "listen() failed: " << WSAGetLastError() << "\n";
#else
            perror("listen");
#endif
            return false;
        }
        std::cout << "Listening on http://0.0.0.0:" << port << " (GET /metrics)\n";
        return true;
    }

    void stop() {
#ifdef _WIN32
        if (listen_fd != INVALID_SOCKET) closesocket(listen_fd);
        WSACleanup();
#else
        if (listen_fd >= 0) close(listen_fd);
#endif
    }

    void serve_forever() {
        while (g_running.load()) {
#ifdef _WIN32
            SOCKET c = accept(listen_fd, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
#else
            int c = accept(listen_fd, nullptr, nullptr);
            if (c < 0) continue;
#endif
            std::thread(&HttpServer::handle_client, this,
#ifdef _WIN32
                        c
#else
                        (int)c
#endif
                        ).detach();
        }
    }

    void handle_client(
#ifdef _WIN32
        SOCKET c
#else
        int c
#endif
    ) {
        // read small request
        char buf[4096];
#ifdef _WIN32
        int n = recv(c, buf, sizeof(buf)-1, 0);
#else
        int n = (int)recv(c, buf, sizeof(buf)-1, 0);
#endif
        if (n <= 0) {
#ifdef _WIN32
            closesocket(c);
#else
            close(c);
#endif
            return;
        }
        buf[n] = '\0';
        std::string req(buf);
        // very simple parse: first line method path
        std::istringstream iss(req);
        std::string method, path, ver; iss >> method >> path >> ver;
        std::string body;
        if (method == "GET" && (path == "/metrics" || path == "/metrics/")) {
            body = build_metrics_json();
            send_http_response(c, 200, "OK", "application/json", body);
        } else {
            body = "{\"endpoints\":[\"/metrics\"]}";
            send_http_response(c, 404, "Not Found", "application/json", body);
        }
#ifdef _WIN32
        closesocket(c);
#else
        close(c);
#endif
    }

    std::string build_metrics_json() {
        std::ostringstream o; o.setf(std::ios::fixed); o << std::setprecision(2);
        std::lock_guard<std::mutex> lk(g_metrics.mtx);
        double mem_used_pct = 0.0;
        if (g_metrics.mem_total) {
            double used = (double)(g_metrics.mem_total - g_metrics.mem_available);
            mem_used_pct = (used / (double)g_metrics.mem_total) * 100.0;
        }
        o << "{\n";
        o << "  \"cpu\": { \"percent\": " << g_metrics.cpu_percent << " },\n";
        o << "  \"memory\": { \"total_bytes\": " << g_metrics.mem_total
          << ", \"available_bytes\": " << g_metrics.mem_available
          << ", \"used_percent\": " << mem_used_pct << " },\n";
        o << "  \"network\": { \"rx_bytes_total\": " << g_metrics.net_rx_bytes_total
          << ", \"tx_bytes_total\": " << g_metrics.net_tx_bytes_total
          << ", \"rx_bytes_per_sec\": " << g_metrics.net_rx_bytes_per_sec
          << ", \"tx_bytes_per_sec\": " << g_metrics.net_tx_bytes_per_sec << " },\n";
        o << "  \"disk\": { \"reads_per_sec\": " << g_metrics.disk_reads_per_sec
          << ", \"writes_per_sec\": " << g_metrics.disk_writes_per_sec
          << ", \"total_iops\": " << (g_metrics.disk_reads_per_sec + g_metrics.disk_writes_per_sec) << " }\n";
        o << "}\n";
        return o.str();
    }

    void send_http_response(
#ifdef _WIN32
        SOCKET c,
#else
        int c,
#endif
        int status, const std::string& reason, const std::string& content_type, const std::string& body) {
        std::ostringstream h;
        h << "HTTP/1.1 " << status << ' ' << reason << "\r\n";
        h << "Content-Type: " << content_type << "\r\n";
        h << "Access-Control-Allow-Origin: *\r\n";
        h << "Content-Length: " << body.size() << "\r\n";
        h << "Connection: close\r\n\r\n";
        std::string hdr = h.str();
#ifdef _WIN32
        send(c, hdr.c_str(), (int)hdr.size(), 0);
        send(c, body.c_str(), (int)body.size(), 0);
#else
        ::send(c, hdr.c_str(), hdr.size(), 0);
        ::send(c, body.c_str(), body.size(), 0);
#endif
    }
};

// ------------------ main ------------------
int main(int argc, char** argv) {
    uint16_t port = parse_port(argc, argv, 8080);

    // start sampler thread
#ifdef _WIN32
    std::thread sampler(sampler_win);
#else
    std::thread sampler(sampler_linux);
#endif

    HttpServer srv;
    if (!srv.start(port)) {
        g_running.store(false);
        sampler.join();
        return 1;
    }

    // graceful shutdown on Ctrl+C
    std::atomic<bool> stop{false};
    std::thread waiter([&](){
        // Simple stdin wait (press Enter to stop) for portability
        std::string tmp; std::getline(std::cin, tmp);
        stop.store(true);
    });

    std::thread looper([&](){ srv.serve_forever(); });

    while (!stop.load()) std::this_thread::sleep_for(200ms);

    g_running.store(false);
#ifdef _WIN32
    // closesocket in stop()
#endif
    srv.stop();
    looper.join();
    sampler.join();
    waiter.join();

    return 0;
}
