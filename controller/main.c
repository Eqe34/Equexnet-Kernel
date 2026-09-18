

#include <winsock2.h>
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <conio.h>
#include <winioctl.h>
#include <stdint.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#define EQUEX_DEVICE_PATH "\\\\.\\EquexNet"
#define EQUEX_DEVICE_TYPE 0x8000

#define IOCTL_EQUEX_GET_PACKET  CTL_CODE(EQUEX_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_BLOCK_IP    CTL_CODE(EQUEX_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_UNBLOCK_IP  CTL_CODE(EQUEX_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_START_WFP   CTL_CODE(EQUEX_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_STOP_WFP    CTL_CODE(EQUEX_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_GET_STATS   CTL_CODE(EQUEX_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_CLEAR_STATS CTL_CODE(EQUEX_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_PACKET_SIZE 2048
#define MAX_BLOCKED_IPS 512
#define MAX_TRACKED_IPS 100
#define SCAN_THRESHOLD 15
#define SCAN_WINDOW_SEC 10
#define BF_THRESHOLD 20
#define BF_WINDOW_SEC 30
#define ICMP_FLOOD_THRESHOLD 80
#define ICMP_FLOOD_WINDOW_SEC 3

#define CLR_RST "\x1b[0m"
#define CLR_RED "\x1b[31m\x1b[1m"
#define CLR_GRN "\x1b[32m"
#define CLR_YLW "\x1b[33m\x1b[1m"
#define CLR_BLU "\x1b[34m"
#define CLR_CYN "\x1b[36m"
#define CLR_MAG "\x1b[35m\x1b[1m"

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#pragma pack(push, 1)
typedef struct _IP_HEADER {
    BYTE ver_ihl;
    BYTE tos;
    WORD total_len;
    WORD id;
    WORD flags_fo;
    BYTE ttl;
    BYTE protocol;
    WORD checksum;
    DWORD src_addr;
    DWORD dest_addr;
} IP_HEADER;

typedef struct _TCP_HEADER {
    WORD src_port;
    WORD dest_port;
    DWORD sequence;
    DWORD acknowledge;
    BYTE data_offset_res;
    BYTE flags;
    WORD window;
    WORD checksum;
    WORD urgent_ptr;
} TCP_HEADER;

typedef struct _UDP_HEADER {
    WORD src_port;
    WORD dest_port;
    WORD length;
    WORD checksum;
} UDP_HEADER;
#pragma pack(pop)

/* Must exactly match the kernel ABI. */
typedef struct _EQUEX_PACKET_RESPONSE {
    ULONG Length;
    LARGE_INTEGER Timestamp;
    UCHAR Data[MAX_PACKET_SIZE];
} EQUEX_PACKET_RESPONSE;

typedef struct _EQUEX_IP_REQUEST {
    ULONG IpAddress;
} EQUEX_IP_REQUEST;

typedef struct _EQUEX_STATISTICS {
    LONGLONG TotalPackets;
    LONGLONG PermittedPackets;
    LONGLONG BlockedPackets;
    LONGLONG DroppedPackets;
    LONGLONG MalformedPackets;
    LONG CurrentBlockedIPs;
    LONG RingBufferEntries;
    LONGLONG LastPacketTime;
} EQUEX_STATISTICS;

typedef struct {
    long total_packets;
    long tcp_packets;
    long udp_packets;
    long icmp_packets;
    long total_bytes;
    time_t start_time;
} Statistics;

typedef struct {
    DWORD src_ip;
    WORD ports[SCAN_THRESHOLD];
    int port_count;
    time_t first_seen;
    int alarm_count;
} PortScanTracker;

typedef struct {
    DWORD src_ip;
    int attempt_count;
    time_t first_seen;
    WORD target_port;
    int alarm_count;
} BruteForceTracker;

static HANDLE g_driver = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_stats_cs;
static CRITICAL_SECTION g_log_cs;
static volatile LONG g_running = 1;
static volatile LONG g_wfp_started = 0;
static volatile LONG g_shutdown_started = 0;

static Statistics g_stats = {0};
static PortScanTracker g_scan[MAX_TRACKED_IPS];
static int g_scan_count = 0;
static BruteForceTracker g_bf[MAX_TRACKED_IPS];
static int g_bf_count = 0;
static time_t g_last_icmp_time = 0;
static int g_icmp_burst = 0;
static DWORD g_blocked[MAX_BLOCKED_IPS];
static int g_blocked_count = 0;
static int g_auto_block = 1;
static FILE* g_log = NULL;

static void SetupANSI(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &mode)) {
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

/* [DEBUG] "sc query bfe" ile ayni bilgiyi program ici kontrol eder.
   WFP tabanli her kernel callout, BFE (Base Filtering Engine) servisi
   calismiyorsa FwpmEngineOpen0 asamasinda basarisiz olur. */
static const char* BfeStateName(DWORD state)
{
    switch (state) {
    case SERVICE_STOPPED:          return "STOPPED";
    case SERVICE_START_PENDING:    return "START_PENDING";
    case SERVICE_STOP_PENDING:     return "STOP_PENDING";
    case SERVICE_RUNNING:          return "RUNNING";
    case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
    case SERVICE_PAUSED:           return "PAUSED";
    default:                       return "UNKNOWN";
    }
}

static void CheckBfeService(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        printf(CLR_YLW "[!] SCM acilamadi, BFE kontrolu atlandi. Win32=%lu\n" CLR_RST,
               GetLastError());
        return;
    }

    SC_HANDLE svc = OpenServiceA(scm, "BFE", SERVICE_QUERY_STATUS);
    if (!svc) {
        printf(CLR_YLW "[!] BFE servis handle'i acilamadi. Win32=%lu\n" CLR_RST,
               GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded = 0;
    ZeroMemory(&ssp, sizeof(ssp));

    if (QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(ssp),
            &bytesNeeded))
    {
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            printf(CLR_GRN "[+] BFE (Base Filtering Engine) calisiyor.\n" CLR_RST);
        } else {
            printf(CLR_RED "[-] BFE calismiyor! Durum: %s (%lu)\n" CLR_RST,
                   BfeStateName(ssp.dwCurrentState), ssp.dwCurrentState);
            printf("    WFP/FwpmEngineOpen0 icin BFE servisinin RUNNING olmasi gerekir.\n");
            printf("    Duzeltmek icin (yonetici olarak): sc start bfe\n");
        }
    } else {
        printf(CLR_YLW "[!] BFE durumu sorgulanamadi. Win32=%lu\n" CLR_RST, GetLastError());
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static void IpToStr(DWORD ip_network, char* buf, size_t bufSize)
{
    struct in_addr addr;
    const char* text;

    if (!buf || bufSize == 0) return;

    addr.s_addr = ip_network;
    text = inet_ntoa(addr);

    if (!text) {
        strncpy(buf, "0.0.0.0", bufSize - 1);
        buf[bufSize - 1] = '\0';
        return;
    }

    strncpy(buf, text, bufSize - 1);
    buf[bufSize - 1] = '\0';
}

static void LogAlert(const char* type, const char* src, const char* msg)
{
    EnterCriticalSection(&g_log_cs);
    if (!g_log) g_log = fopen("equexnet_alerts.log", "a");
    if (g_log) {
        time_t now = time(NULL);
        struct tm* tmv;
        char ts[64];
        tmv = localtime(&now);
        if (tmv) {
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tmv);
        } else {
            strncpy(ts, "0000-00-00 00:00:00", sizeof(ts) - 1);
            ts[sizeof(ts) - 1] = '\0';
        }
        fprintf(g_log, "[%s] [%s] SRC: %s | %s\n", ts, type, src, msg);
        fflush(g_log);
    }
    LeaveCriticalSection(&g_log_cs);
}

static int IsAlreadyBlocked(DWORD ip)
{
    int found = 0;
    EnterCriticalSection(&g_stats_cs);
    for (int i = 0; i < g_blocked_count; ++i) {
        if (g_blocked[i] == ip) { found = 1; break; }
    }
    LeaveCriticalSection(&g_stats_cs);
    return found;
}

static void BlockIP(const char* ipStr, DWORD ip, const char* reason)
{
    if (!g_auto_block || g_driver == INVALID_HANDLE_VALUE || ip == 0 || ip == 0xFFFFFFFFUL)
        return;

    EnterCriticalSection(&g_stats_cs);
    if (g_blocked_count >= MAX_BLOCKED_IPS) {
        LeaveCriticalSection(&g_stats_cs);
        return;
    }
    for (int i = 0; i < g_blocked_count; ++i) {
        if (g_blocked[i] == ip) {
            LeaveCriticalSection(&g_stats_cs);
            return;
        }
    }
    LeaveCriticalSection(&g_stats_cs);

    EQUEX_IP_REQUEST req;
    DWORD bytesRet = 0;
    req.IpAddress = ip;

    BOOL ok = DeviceIoControl(
        g_driver,
        IOCTL_EQUEX_BLOCK_IP,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytesRet,
        NULL);

    if (ok) {
        EnterCriticalSection(&g_stats_cs);
        if (g_blocked_count < MAX_BLOCKED_IPS) {
            g_blocked[g_blocked_count++] = ip;
        }
        LeaveCriticalSection(&g_stats_cs);
        printf(CLR_MAG "\n[KERNEL BLOCK] %s\n" CLR_RST, ipStr);
        printf(" Sebep: %s\n\n", reason);
        LogAlert("KERNEL_BLOCK", ipStr, reason);
    } else {
        printf(CLR_YLW "[!] Kernel block basarisiz: %s (Win32=%lu)\n" CLR_RST,
               ipStr, GetLastError());
    }
}

static void UnblockAll(void)
{
    if (g_driver == INVALID_HANDLE_VALUE) return;

    DWORD bytesRet = 0;
    BOOL ok = DeviceIoControl(
        g_driver,
        IOCTL_EQUEX_UNBLOCK_IP,
        NULL,
        0,
        NULL,
        0,
        &bytesRet,
        NULL);

    EnterCriticalSection(&g_stats_cs);
    g_blocked_count = 0;
    LeaveCriticalSection(&g_stats_cs);

    if (ok) printf(CLR_GRN "[+] Kernel blacklist temizlendi.\n" CLR_RST);
    else printf(CLR_YLW "[!] Kernel blacklist temizleme basarisiz (Win32=%lu).\n" CLR_RST, GetLastError());
}

static int StartWfp(void)
{
    if (g_driver == INVALID_HANDLE_VALUE) return 0;
    if (InterlockedCompareExchange(&g_wfp_started, 1, 1) != 0) return 1;

    DWORD bytesRet = 0;
    BOOL ok = DeviceIoControl(
        g_driver,
        IOCTL_EQUEX_START_WFP,
        NULL, 0, NULL, 0, &bytesRet, NULL);

    if (ok) {
        InterlockedExchange(&g_wfp_started, 1);
        printf(CLR_GRN "[+] WFP baslatildi.\n" CLR_RST);
        return 1;
    }

    printf(CLR_RED "[-] WFP baslatilamadi. Win32=%lu\n" CLR_RST, GetLastError());
    printf(CLR_YLW "    Gercek NTSTATUS icin DebugView (Sysinternals) ile\n"
                   "    kernel debug ciktisini izleyin ve \"EQUEX\" filtresi girin.\n" CLR_RST);
    return 0;
}

static void StopWfp(void)
{
    if (g_driver == INVALID_HANDLE_VALUE) return;
    if (InterlockedExchange(&g_wfp_started, 0) == 0) return;

    DWORD bytesRet = 0;
    BOOL ok = DeviceIoControl(
        g_driver,
        IOCTL_EQUEX_STOP_WFP,
        NULL, 0, NULL, 0, &bytesRet, NULL);

    if (ok) printf(CLR_GRN "[+] WFP durduruldu.\n" CLR_RST);
    else printf(CLR_YLW "[!] WFP durdurma basarisiz. Win32=%lu\n" CLR_RST, GetLastError());
}

static void PrintKernelStats(void)
{
    if (g_driver == INVALID_HANDLE_VALUE) return;

    EQUEX_STATISTICS ks;
    DWORD bytesRet = 0;
    ZeroMemory(&ks, sizeof(ks));

    if (!DeviceIoControl(g_driver, IOCTL_EQUEX_GET_STATS,
                         NULL, 0, &ks, sizeof(ks), &bytesRet, NULL)) {
        printf(CLR_YLW "[!] Kernel istatistikleri alinamadi. Win32=%lu\n" CLR_RST, GetLastError());
        return;
    }

    printf(CLR_CYN
           "\n=== KERNEL ISTATISTIK ===\n"
           "Total            : %lld\n"
           "Permitted        : %lld\n"
           "Blocked          : %lld\n"
           "Dropped          : %lld\n"
           "Malformed        : %lld\n"
           "Blocked IP       : %ld\n"
           "Ring entries     : %ld\n"
           "=======================\n" CLR_RST,
           ks.TotalPackets,
           ks.PermittedPackets,
           ks.BlockedPackets,
           ks.DroppedPackets,
           ks.MalformedPackets,
           ks.CurrentBlockedIPs,
           ks.RingBufferEntries);
}

static void ResetKernelStats(void)
{
    if (g_driver == INVALID_HANDLE_VALUE) return;
    DWORD bytesRet = 0;
    if (!DeviceIoControl(g_driver, IOCTL_EQUEX_CLEAR_STATS,
                         NULL, 0, NULL, 0, &bytesRet, NULL)) {
        printf(CLR_YLW "[!] Kernel istatistik sifirlama basarisiz. Win32=%lu\n" CLR_RST, GetLastError());
    } else {
        printf(CLR_GRN "[+] Kernel istatistikleri sifirlandi.\n" CLR_RST);
    }
}

static void DetectPortScan(DWORD src_ip, WORD dst_port, const char* src_str)
{
    time_t now = time(NULL);
    for (int i = 0; i < g_scan_count; ++i) {
        if (g_scan[i].src_ip != src_ip) continue;

        if (difftime(now, g_scan[i].first_seen) > SCAN_WINDOW_SEC) {
            g_scan[i].port_count = 0;
            g_scan[i].first_seen = now;
        }

        for (int p = 0; p < g_scan[i].port_count; ++p)
            if (g_scan[i].ports[p] == dst_port) return;

        if (g_scan[i].port_count < SCAN_THRESHOLD)
            g_scan[i].ports[g_scan[i].port_count++] = dst_port;

        if (g_scan[i].port_count >= SCAN_THRESHOLD && g_scan[i].alarm_count == 0) {
            g_scan[i].alarm_count++;
            printf(CLR_RED "\n[ALARM] PORT SCAN: %s (%d port)\n" CLR_RST,
                   src_str, g_scan[i].port_count);
            LogAlert("PORT_SCAN", src_str, "Port scan esigi asildi");
            BlockIP(src_str, src_ip, "Port scan tespiti");
        }
        return;
    }

    if (g_scan_count < MAX_TRACKED_IPS) {
        int idx = g_scan_count++;
        ZeroMemory(&g_scan[idx], sizeof(g_scan[idx]));
        g_scan[idx].src_ip = src_ip;
        g_scan[idx].ports[0] = dst_port;
        g_scan[idx].port_count = 1;
        g_scan[idx].first_seen = now;
    }
}

static void DetectBruteForce(DWORD src_ip, WORD dst_port, BYTE flags, const char* src_str)
{
    if (!(flags & 0x02)) return;
    if (dst_port != 21 && dst_port != 22 && dst_port != 23 && dst_port != 3389 && dst_port != 445) return;

    time_t now = time(NULL);
    for (int i = 0; i < g_bf_count; ++i) {
        if (g_bf[i].src_ip != src_ip || g_bf[i].target_port != dst_port) continue;

        if (difftime(now, g_bf[i].first_seen) > BF_WINDOW_SEC) {
            g_bf[i].attempt_count = 0;
            g_bf[i].first_seen = now;
        }

        g_bf[i].attempt_count++;
        if (g_bf[i].attempt_count >= BF_THRESHOLD && g_bf[i].alarm_count == 0) {
            g_bf[i].alarm_count++;
            printf(CLR_RED "\n[ALARM] BRUTE FORCE: %s -> port %u (%d deneme)\n" CLR_RST,
                   src_str, dst_port, g_bf[i].attempt_count);
            LogAlert("BRUTE_FORCE", src_str, "Brute-force esigi asildi");
            BlockIP(src_str, src_ip, "Brute force tespiti");
        }
        return;
    }

    if (g_bf_count < MAX_TRACKED_IPS) {
        int idx = g_bf_count++;
        ZeroMemory(&g_bf[idx], sizeof(g_bf[idx]));
        g_bf[idx].src_ip = src_ip;
        g_bf[idx].target_port = dst_port;
        g_bf[idx].attempt_count = 1;
        g_bf[idx].first_seen = now;
    }
}

static void DetectICMPFlood(const char* src_str, DWORD src_ip)
{
    time_t now = time(NULL);
    if (difftime(now, g_last_icmp_time) > ICMP_FLOOD_WINDOW_SEC) {
        g_icmp_burst = 0;
        g_last_icmp_time = now;
    }

    g_icmp_burst++;
    if (g_icmp_burst >= ICMP_FLOOD_THRESHOLD) {
        g_icmp_burst = 0;
        printf(CLR_RED "\n[ALARM] ICMP FLOOD: %s\n" CLR_RST, src_str);
        LogAlert("ICMP_FLOOD", src_str, "ICMP flood esigi asildi");
        BlockIP(src_str, src_ip, "ICMP flood tespiti");
    }
}

static void DetectWebAttacks(const char* payload, int len, const char* src_str, DWORD src_ip)
{
    if (len <= 0) return;

    char buf[512] = {0};
    int cp = (len < (int)sizeof(buf) - 1) ? len : (int)sizeof(buf) - 1;
    memcpy(buf, payload, cp);
    for (int i = 0; i < cp; ++i)
        buf[i] = (char)toupper((unsigned char)buf[i]);

    if (strstr(buf, "UNION SELECT") || strstr(buf, "DROP TABLE") ||
        strstr(buf, "OR 1=1") || strstr(buf, "' OR '")) {
        printf(CLR_RED "\n[ALARM] SQL INJECTION: %s\n" CLR_RST, src_str);
        LogAlert("SQL_INJECT", src_str, "Payload eslesmesi");
        BlockIP(src_str, src_ip, "SQL injection payload");
    } else if (strstr(buf, "<SCRIPT>") || strstr(buf, "ONERROR=") || strstr(buf, "JAVASCRIPT:")) {
        printf(CLR_RED "\n[ALARM] XSS: %s\n" CLR_RST, src_str);
        LogAlert("XSS", src_str, "Payload eslesmesi");
        BlockIP(src_str, src_ip, "XSS payload");
    } else if (strstr(buf, "../") || strstr(buf, "..\\") || strstr(buf, "/ETC/PASSWD")) {
        printf(CLR_RED "\n[ALARM] PATH TRAVERSAL: %s\n" CLR_RST, src_str);
        LogAlert("PATH_TRAV", src_str, "Payload eslesmesi");
        BlockIP(src_str, src_ip, "Path traversal");
    }
}

static void ProcessPacket(const UCHAR* buffer, int data_size)
{
    if (!buffer || data_size < (int)sizeof(IP_HEADER)) return;

    const IP_HEADER* ip = (const IP_HEADER*)buffer;
    if ((ip->ver_ihl >> 4) != 4) return;

    int ip_hl = (ip->ver_ihl & 0x0F) * 4;
    if (ip_hl < 20 || data_size < ip_hl) return;

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    IpToStr(ip->src_addr, src, sizeof(src));
    IpToStr(ip->dest_addr, dst, sizeof(dst));

    EnterCriticalSection(&g_stats_cs);
    g_stats.total_packets++;
    g_stats.total_bytes += data_size;
    LeaveCriticalSection(&g_stats_cs);

    switch (ip->protocol) {
    case 6: {
        EnterCriticalSection(&g_stats_cs);
        g_stats.tcp_packets++;
        LeaveCriticalSection(&g_stats_cs);

        if (data_size < ip_hl + (int)sizeof(TCP_HEADER)) return;
        const TCP_HEADER* tcp = (const TCP_HEADER*)(buffer + ip_hl);
        int tcp_hl = ((tcp->data_offset_res >> 4) & 0x0F) * 4;
        if (tcp_hl < 20 || data_size < ip_hl + tcp_hl) return;

        WORD sport = ntohs(tcp->src_port);
        WORD dport = ntohs(tcp->dest_port);
        int payload_len = data_size - ip_hl - tcp_hl;

        printf(CLR_BLU "[TCP] %s:%u -> %s:%u | Flags: 0x%02X | Bytes: %d\n" CLR_RST,
               src, sport, dst, dport, tcp->flags, data_size);

        if ((tcp->flags & 0x02) && !(tcp->flags & 0x10)) {
            DetectPortScan(ip->src_addr, dport, src);
            DetectBruteForce(ip->src_addr, dport, tcp->flags, src);
        }

        if ((tcp->flags & 0x01) && (tcp->flags & 0x08) && (tcp->flags & 0x20)) {
            LogAlert("SCAN_XMAS", src, "FIN+PSH+URG");
            BlockIP(src, ip->src_addr, "XMAS scan");
        } else if (tcp->flags == 0x00) {
            LogAlert("SCAN_NULL", src, "Tum TCP flaglari sifir");
            BlockIP(src, ip->src_addr, "NULL scan");
        } else if ((tcp->flags & 0x02) && (tcp->flags & 0x01)) {
            LogAlert("MALFORMED_PKT", src, "SYN+FIN");
            BlockIP(src, ip->src_addr, "SYN+FIN malformed");
        }

        if (payload_len > 0) {
            if ((dport == 80 || dport == 8080 || dport == 8000 ||
                 sport == 80 || sport == 8080 || sport == 8000)) {
                int cp = payload_len < 511 ? payload_len : 511;
                char payload[512] = {0};
                memcpy(payload, buffer + ip_hl + tcp_hl, cp);
                DetectWebAttacks(payload, cp, src, ip->src_addr);
            }
        }
        break;
    }
    case 17: {
        EnterCriticalSection(&g_stats_cs);
        g_stats.udp_packets++;
        LeaveCriticalSection(&g_stats_cs);
        if (data_size < ip_hl + (int)sizeof(UDP_HEADER)) return;
        const UDP_HEADER* udp = (const UDP_HEADER*)(buffer + ip_hl);
        printf(CLR_CYN "[UDP] %s:%u -> %s:%u | Bytes: %d\n" CLR_RST,
               src, ntohs(udp->src_port), dst, ntohs(udp->dest_port), data_size);
        break;
    }
    case 1:
        EnterCriticalSection(&g_stats_cs);
        g_stats.icmp_packets++;
        LeaveCriticalSection(&g_stats_cs);
        printf(CLR_YLW "[ICMP] %s -> %s | Bytes: %d\n" CLR_RST, src, dst, data_size);
        DetectICMPFlood(src, ip->src_addr);
        break;
    default:
        break;
    }
}

static void PrintStatistics(void)
{
    EnterCriticalSection(&g_stats_cs);
    printf(CLR_CYN
           "\n=== CONTROLLER ISTATISTIK ===\n"
           "Packets: %ld | TCP: %ld | UDP: %ld | ICMP: %ld\n"
           "Bytes  : %ld | Blocked IP: %d\n"
           "=============================\n" CLR_RST,
           g_stats.total_packets,
           g_stats.tcp_packets,
           g_stats.udp_packets,
           g_stats.icmp_packets,
           g_stats.total_bytes,
           g_blocked_count);
    LeaveCriticalSection(&g_stats_cs);

    PrintKernelStats();
}

static void Shutdown(void)
{
    if (InterlockedExchange(&g_shutdown_started, 1) != 0) return;
    InterlockedExchange(&g_running, 0);

    UnblockAll();
    StopWfp();

    if (g_log) {
        EnterCriticalSection(&g_log_cs);
        if (g_log) {
            fclose(g_log);
            g_log = NULL;
        }
        LeaveCriticalSection(&g_log_cs);
    }

    if (g_driver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_driver);
        g_driver = INVALID_HANDLE_VALUE;
    }
}

static BOOL WINAPI ConsoleHandler(DWORD ctrlType)
{
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        Shutdown();
        return TRUE;
    default:
        return FALSE;
    }
}

static void CheckKeyboard(void)
{
    if (!_kbhit()) return;
    int key = _getch();

    switch (key) {
    case 's': case 'S':
        PrintStatistics();
        break;
    case 'b': case 'B':
        g_auto_block = !g_auto_block;
        printf(g_auto_block ? CLR_GRN "[+] Otomatik kernel block AKTIF.\n" CLR_RST
                            : CLR_YLW "[-] Otomatik kernel block PASIF.\n" CLR_RST);
        break;
    case 'u': case 'U':
        UnblockAll();
        break;
    case 'r': case 'R':
        ResetKernelStats();
        break;
    case 'q': case 'Q':
        Shutdown();
        break;
    }
}

int main(void)
{
    SetupANSI();
    InitializeCriticalSection(&g_stats_cs);
    InitializeCriticalSection(&g_log_cs);
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    printf(CLR_GRN
           "=====================================================\n"
           " EQUEXNET ANALYZER v2.0 - STABLE KERNEL CONTROLLER\n"
           "=====================================================\n" CLR_RST);

    CheckBfeService();

    g_driver = CreateFileA(
        EQUEX_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_driver == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf(CLR_RED "[-] Driver acilamadi. Win32=%lu\n" CLR_RST, err);
        printf("    Device path: %s\n", EQUEX_DEVICE_PATH);
        printf("    Kernel symbolic link \"\\DosDevices\\EquexNet\" olmalidir.\n");
        goto cleanup;
    }

    printf(CLR_GRN "[+] Kernel driver handle acildi.\n" CLR_RST);

    if (!StartWfp()) goto cleanup;

    EnterCriticalSection(&g_stats_cs);
    g_stats.start_time = time(NULL);
    LeaveCriticalSection(&g_stats_cs);

    printf(CLR_GRN
           "\nSistem aktif.\n"
           " [S] Kernel + controller istatistik\n"
           " [B] Auto block ac/kapa\n"
           " [U] Tum kernel blocklarini temizle\n"
           " [R] Kernel istatistiklerini sifirla\n"
           " [Q] Cikis\n\n" CLR_RST);

    EQUEX_PACKET_RESPONSE packet;

    while (InterlockedCompareExchange(&g_running, 1, 1) != 0) {
        CheckKeyboard();
        if (InterlockedCompareExchange(&g_running, 1, 1) == 0) break;

        DWORD bytesRead = 0;
        ZeroMemory(&packet, sizeof(packet));

        BOOL ok = DeviceIoControl(
            g_driver,
            IOCTL_EQUEX_GET_PACKET,
            NULL,
            0,
            &packet,
            sizeof(packet),
            &bytesRead,
            NULL);

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS || err == ERROR_NO_MORE_FILES || err == ERROR_NOT_FOUND) {
                Sleep(1);
                continue;
            }
            if (err == ERROR_DEVICE_NOT_CONNECTED || err == ERROR_INVALID_HANDLE) {
                printf(CLR_RED "[-] Driver baglantisi koptu. Win32=%lu\n" CLR_RST, err);
                break;
            }
            printf(CLR_YLW "[!] GET_PACKET basarisiz. Win32=%lu\n" CLR_RST, err);
            Sleep(10);
            continue;
        }

        if (bytesRead < sizeof(ULONG)) {
            Sleep(1);
            continue;
        }

        if (packet.Length == 0 || packet.Length > MAX_PACKET_SIZE) {
            printf(CLR_YLW "[!] Gecersiz paket uzunlugu: %lu\n" CLR_RST, packet.Length);
            continue;
        }

        if (bytesRead < sizeof(EQUEX_PACKET_RESPONSE)) {
            printf(CLR_YLW "[!] Incomplete packet response: %lu byte\n" CLR_RST, bytesRead);
            continue;
        }

        ProcessPacket(packet.Data, (int)packet.Length);
    }

cleanup:
    Shutdown();
    SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    DeleteCriticalSection(&g_log_cs);
    DeleteCriticalSection(&g_stats_cs);
    return 0;
}
