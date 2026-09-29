#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>
#include <time.h>
#include <string.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

#define DNS_PORT 53
#define TIMEOUT_MS 1200
#define SAMPLE_COUNT 3
#define CHECK_INTERVAL_SECONDS 300

/*
 * Public resolvers. Security-oriented entries are included first:
 * Quad9 blocks known malware/phishing domains; AdGuard and CleanBrowsing
 * provide filtering. All entries are still benchmarked before selection.
 */
static const char *candidates[] = {
    /* Security / privacy oriented */
    "9.9.9.9", "149.112.112.112",       /* Quad9 Secure */
    "94.140.14.14", "94.140.15.15",     /* AdGuard DNS */
    "185.228.168.9", "185.228.169.9",    /* CleanBrowsing Security */
    "1.1.1.1", "1.0.0.1",                /* Cloudflare */
    "8.8.8.8", "8.8.4.4",                /* Google Public DNS */
    "208.67.222.222", "208.67.220.220",  /* Cisco OpenDNS */
    /* Mainland China options, often lower latency in China */
    "223.5.5.5", "223.6.6.6",            /* Alibaba */
    "119.29.29.29",                       /* Tencent */
    "114.114.114.114", "114.114.115.115" /* 114DNS */
};
static const char *test_names[] = {"www.microsoft.com", "www.qq.com", "www.baidu.com"};

typedef struct { char ip[INET_ADDRSTRLEN]; double ms; int ok; } Result;

static void log_line(const char *s) {
    SYSTEMTIME t; GetLocalTime(&t);
    printf("[%02u:%02u:%02u] %s\n", t.wHour, t.wMinute, t.wSecond, s);
    fflush(stdout);
}

static int make_query(const char *name, unsigned char *buf, int cap, unsigned short id) {
    int n = snprintf((char *)buf + 12, cap - 12, "%s", name);
    if (n < 0 || n >= cap - 12) return 0;
    int p = 12;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t len = dot ? (size_t)(dot - s) : strlen(s);
        if (!len || len > 63 || p + (int)len + 6 >= cap) return 0;
        buf[p++] = (unsigned char)len;
        memcpy(buf + p, s, len); p += (int)len;
        if (!dot) break;
        s = dot + 1;
    }
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 1; buf[p++] = 0; buf[p++] = 1;
    buf[0] = (unsigned char)(id >> 8); buf[1] = (unsigned char)id;
    buf[2] = 1; buf[3] = 0; buf[4] = 0; buf[5] = 1;
    memset(buf + 6, 0, 6);
    return p;
}

static double probe_once(const char *server, const char *name) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return -1;
    DWORD timeout = TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(DNS_PORT);
    if (InetPtonA(AF_INET, server, &addr.sin_addr) != 1) { closesocket(sock); return -1; }

    unsigned char query[512] = {0}, reply[1500];
    unsigned short id = (unsigned short)(GetTickCount() ^ (unsigned)GetCurrentThreadId());
    int qlen = make_query(name, query, sizeof(query), id);
    if (!qlen) { closesocket(sock); return -1; }
    LARGE_INTEGER start, end, freq; QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&start);
    int sent = sendto(sock, (const char *)query, qlen, 0, (struct sockaddr *)&addr, sizeof(addr));
    int got = sent == qlen ? recvfrom(sock, (char *)reply, sizeof(reply), 0, NULL, NULL) : SOCKET_ERROR;
    QueryPerformanceCounter(&end); closesocket(sock);
    if (got < 12 || reply[0] != query[0] || reply[1] != query[1] || !(reply[2] & 0x80) || (reply[3] & 0x0f) != 0)
        return -1;
    return (double)(end.QuadPart - start.QuadPart) * 1000.0 / (double)freq.QuadPart;
}

static Result measure(const char *ip) {
    Result r; strncpy(r.ip, ip, sizeof(r.ip)); r.ip[sizeof(r.ip)-1] = 0;
    r.ms = 0; r.ok = 0;
    for (int i = 0; i < SAMPLE_COUNT; i++) {
        double ms = probe_once(ip, test_names[i]);
        if (ms >= 0) { r.ms += ms; r.ok++; }
    }
    if (r.ok) r.ms /= r.ok; else r.ms = 1e9;
    return r;
}

static IP_ADAPTER_ADDRESSES *active_adapter(IP_ADAPTER_ADDRESSES **allocation) {
    ULONG size = 15000;
    IP_ADAPTER_ADDRESSES *list = NULL;
    ULONG rc;
    *allocation = NULL;
    do {
        list = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!list) return NULL;
        rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, list, &size);
        if (rc == ERROR_BUFFER_OVERFLOW) { free(list); list = NULL; }
    } while (rc == ERROR_BUFFER_OVERFLOW);
    if (rc != NO_ERROR) { free(list); return NULL; }
    *allocation = list;
    for (IP_ADAPTER_ADDRESSES *a = list; a; a = a->Next) {
        if (a->OperStatus == IfOperStatusUp && a->FirstGatewayAddress && a->FirstDnsServerAddress && a->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
            return a;
    }
    free(list); *allocation = NULL; return NULL;
}

static int set_dns(const wchar_t *alias, const char *primary, const char *secondary) {
    wchar_t cmd[1024]; STARTUPINFOW si; PROCESS_INFORMATION pi;
    for (int i = 0; i < 2; i++) {
        if (i == 0)
            swprintf(cmd, 1024, L"netsh.exe interface ipv4 set dnsservers name=\"%ls\" static %hs primary validate=no", alias, primary);
        else
            swprintf(cmd, 1024, L"netsh.exe interface ipv4 add dnsservers name=\"%ls\" address=%hs index=2 validate=no", alias, secondary);
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si); memset(&pi, 0, sizeof(pi));
        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 0;
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        if (code != 0) return 0;
    }
    return 1;
}

static void scan(int apply) {
    IP_ADAPTER_ADDRESSES *allocation = NULL;
    IP_ADAPTER_ADDRESSES *adapter = active_adapter(&allocation);
    if (!adapter) { log_line("No active IPv4 adapter with gateway and DNS found."); return; }
    char current[INET_ADDRSTRLEN] = "";
    struct sockaddr_in *dns = (struct sockaddr_in *)adapter->FirstDnsServerAddress->Address.lpSockaddr;
    InetNtopA(AF_INET, &dns->sin_addr, current, sizeof(current));
    wprintf(L"Adapter: %s | current DNS: %S\n", adapter->FriendlyName, current);

    Result best = {"", 1e9, 0};
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        Result r = measure(candidates[i]);
        printf("  %-16s %s", r.ip, r.ok ? "" : "unavailable");
        if (r.ok) printf("%6.1f ms (%d/%d replies)", r.ms, r.ok, SAMPLE_COUNT);
        putchar('\n');
        if (r.ok && r.ms < best.ms) best = r;
    }
    Result cur = measure(current);
    if (!best.ok) { log_line("No candidate DNS responded; keeping current settings."); free(allocation); return; }
    printf("Best: %s (%.1f ms); current %s (%s%.1f ms)\n", best.ip, best.ms, current, cur.ok ? "" : "unavailable, ", cur.ms);
    if (_stricmp(best.ip, current) == 0) { log_line("Current DNS is already the fastest candidate."); free(allocation); return; }
    if (cur.ok && best.ms > cur.ms * 0.80) { log_line("Improvement is under 20%; keeping current DNS."); free(allocation); return; }
    if (!apply) { log_line("Dry run: use --apply to change DNS automatically."); free(allocation); return; }
    const char *secondary = NULL;
    double secondary_ms = 1e9;
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        if (_stricmp(candidates[i], best.ip) == 0) continue;
        Result r = measure(candidates[i]);
        if (r.ok && r.ms < secondary_ms) { secondary = candidates[i]; secondary_ms = r.ms; }
    }
    if (!secondary) { log_line("Could not find a working secondary DNS; settings unchanged."); free(allocation); return; }
    if (set_dns(adapter->FriendlyName, best.ip, secondary)) {
        printf("DNS updated on %ls: %s, %s\n", adapter->FriendlyName, best.ip, secondary);
    } else {
        log_line("netsh failed to update DNS. Run elevated and check adapter permissions.");
    }
    free(allocation);
}

int main(int argc, char **argv) {
    int apply = 0, monitor = 0;
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--apply") == 0) apply = 1;
        else if (_stricmp(argv[i], "--monitor") == 0) monitor = 1;
        else if (_stricmp(argv[i], "--help") == 0) {
            puts("DNS Optimizer (Windows)\n  dns_optimizer.exe             One-time dry run\n  dns_optimizer.exe --apply     Optimize once and apply\n  dns_optimizer.exe --monitor   Check every 5 minutes (dry run)\n  dns_optimizer.exe --monitor --apply   Auto-optimize every 5 minutes");
            return 0;
        }
    }
    WSADATA wsa; if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { puts("Winsock initialization failed."); return 1; }
    do {
        scan(apply);
        if (monitor) Sleep(CHECK_INTERVAL_SECONDS * 1000UL);
    } while (monitor);
    WSACleanup(); return 0;
}
