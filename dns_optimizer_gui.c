#define main dns_optimizer_console_main
#include "dns_optimizer.c"
#undef main

#define IDC_DETECT 1001
#define IDC_APPLY  1002
#define IDC_OUTPUT 1003
#define IDC_STATUS 1004
#define WM_SCAN_DONE (WM_APP + 1)
#define WM_APPLY_DONE (WM_APP + 2)

static HWND g_output, g_status, g_detect, g_apply;
static HANDLE g_worker;
static volatile LONG g_busy;
static int g_has_best;
static int g_can_apply;
static Result g_best;
static char g_secondary[INET_ADDRSTRLEN];
static wchar_t g_alias[256];
static wchar_t g_report[12000];
static wchar_t g_done_message[512];

static void report_reset(void) { g_report[0] = L'\0'; }
static void report_add(const wchar_t *text) {
    size_t used = wcslen(g_report), left = sizeof(g_report) / sizeof(g_report[0]) - used;
    if (left > 1) wcsncat_s(g_report, sizeof(g_report) / sizeof(g_report[0]), text, left - 1);
}
static void report_add_result(const Result *r) {
    wchar_t line[256];
    if (r->ok)
        _snwprintf_s(line, 256, _TRUNCATE, L"%-16S %6.1f ms  (%d/%d)\r\n", r->ip, r->ms, r->ok, SAMPLE_COUNT);
    else
        _snwprintf_s(line, 256, _TRUNCATE, L"%-16S 不可用\r\n", r->ip);
    report_add(line);
}
static DWORD WINAPI detect_worker(LPVOID unused) {
    (void)unused;
    IP_ADAPTER_ADDRESSES *allocation = NULL;
    IP_ADAPTER_ADDRESSES *adapter = active_adapter(&allocation);
    report_reset(); g_has_best = 0; g_can_apply = 0;
    if (!adapter) {
        wcscpy_s(g_done_message, 512, L"未找到正在使用的 IPv4 网卡。");
        PostMessageW(GetParent(g_output), WM_SCAN_DONE, 0, 0); return 0;
    }
    char current[INET_ADDRSTRLEN] = "";
    struct sockaddr_in *dns = (struct sockaddr_in *)adapter->FirstDnsServerAddress->Address.lpSockaddr;
    InetNtopA(AF_INET, &dns->sin_addr, current, sizeof(current));
    wcsncpy_s(g_alias, 256, adapter->FriendlyName, _TRUNCATE);
    wchar_t header[512];
    _snwprintf_s(header, 512, _TRUNCATE, L"网卡：%s\r\n当前 DNS：%S\r\n\r\n检测结果：\r\n", g_alias, current);
    report_add(header);

    Result best = {"", 1e9, 0};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        Result r = measure(candidates[i]); report_add_result(&r);
        if (r.ok && r.ms < best.ms) best = r;
    }
    Result cur = measure(current);
    if (!best.ok) {
        wcscpy_s(g_done_message, 512, L"没有可用的 DNS，未作任何修改。");
    } else {
        _snwprintf_s(g_done_message, 512, _TRUNCATE, L"最快：%S（%.1f ms），当前：%S（%.1f ms）", best.ip, best.ms, current, cur.ms);
        g_best = best; g_has_best = 1;
        if (_stricmp(best.ip, current) == 0) {
            wcscat_s(g_done_message, 512, L"\r\n当前 DNS 已经是候选中最快的。");
        } else if (cur.ok && best.ms > cur.ms * 0.80) {
            wcscat_s(g_done_message, 512, L"\r\n提升不足 20%，建议保持当前设置。");
        } else {
            double secondary_ms = 1e9;
            for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
                if (_stricmp(candidates[i], best.ip) == 0) continue;
                Result r = measure(candidates[i]);
                if (r.ok && r.ms < secondary_ms) {
                    strncpy_s(g_secondary, sizeof(g_secondary), r.ip, _TRUNCATE);
                    secondary_ms = r.ms;
                    g_can_apply = 1;
                }
            }
            if (!g_can_apply) wcscat_s(g_done_message, 512, L"\r\n没有找到可用的备用 DNS。");
            else wcscat_s(g_done_message, 512, L"\r\n可以点击“替换 DNS”。");
        }
    }
    free(allocation);
    PostMessageW(GetParent(g_output), WM_SCAN_DONE, 0, 0); return 0;
}

static DWORD WINAPI apply_worker(LPVOID unused) {
    (void)unused;
    int ok = set_dns(g_alias, g_best.ip, g_secondary);
    if (ok) _snwprintf_s(g_done_message, 512, _TRUNCATE, L"已替换 DNS：%S，备用：%S", g_best.ip, g_secondary);
    else wcscpy_s(g_done_message, 512, L"替换失败，请确认程序已用管理员身份运行。");
    PostMessageW(GetParent(g_output), WM_APPLY_DONE, 0, 0); return 0;
}

static void start_detect(HWND hwnd) {
    if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;
    EnableWindow(g_detect, FALSE); EnableWindow(g_apply, FALSE);
    SetWindowTextW(g_status, L"正在检测，请稍候……");
    g_worker = CreateThread(NULL, 0, detect_worker, hwnd, 0, NULL);
    if (!g_worker) { InterlockedExchange(&g_busy, 0); EnableWindow(g_detect, TRUE); SetWindowTextW(g_status, L"无法创建检测线程。"); }
}
static void start_apply(HWND hwnd) {
    (void)hwnd;
    if (!g_has_best || !g_can_apply || InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;
    EnableWindow(g_detect, FALSE); EnableWindow(g_apply, FALSE);
    SetWindowTextW(g_status, L"正在替换 DNS，请稍候……");
    g_worker = CreateThread(NULL, 0, apply_worker, NULL, 0, NULL);
    if (!g_worker) { InterlockedExchange(&g_busy, 0); EnableWindow(g_detect, TRUE); EnableWindow(g_apply, TRUE); SetWindowTextW(g_status, L"无法创建替换线程。"); }
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        g_detect = CreateWindowW(L"BUTTON", L"检测 DNS", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 120, 32, hwnd, (HMENU)IDC_DETECT, NULL, NULL);
        g_apply = CreateWindowW(L"BUTTON", L"替换 DNS", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED, 0, 0, 120, 32, hwnd, (HMENU)IDC_APPLY, NULL, NULL);
        g_status = CreateWindowW(L"STATIC", L"点击“检测 DNS”开始", WS_CHILD | WS_VISIBLE, 0, 0, 500, 28, hwnd, (HMENU)IDC_STATUS, NULL, NULL);
        g_output = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 500, 300, hwnd, (HMENU)IDC_OUTPUT, NULL, NULL);
        SendMessageW(g_output, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        return 0;
    case WM_SIZE: {
        int width = LOWORD(lp), height = HIWORD(lp);
        MoveWindow(g_detect, 12, 10, 120, 32, TRUE); MoveWindow(g_apply, 142, 10, 120, 32, TRUE);
        MoveWindow(g_status, 275, 15, width - 287, 24, TRUE);
        MoveWindow(g_output, 12, 52, width - 24, height - 64, TRUE); return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_DETECT) start_detect(hwnd);
        else if (LOWORD(wp) == IDC_APPLY) start_apply(hwnd);
        return 0;
    case WM_SCAN_DONE:
        if (g_worker) { CloseHandle(g_worker); g_worker = NULL; }
        SetWindowTextW(g_output, g_report); SetWindowTextW(g_status, g_done_message);
        EnableWindow(g_detect, TRUE); EnableWindow(g_apply, g_can_apply); InterlockedExchange(&g_busy, 0); return 0;
    case WM_APPLY_DONE:
        if (g_worker) { CloseHandle(g_worker); g_worker = NULL; }
        SetWindowTextW(g_status, g_done_message); EnableWindow(g_detect, TRUE); EnableWindow(g_apply, FALSE); InterlockedExchange(&g_busy, 0); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show) {
    (void)previous; (void)command_line;
    WSADATA wsa; if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    const wchar_t klass[] = L"DNSOptimizerWindow";
    WNDCLASSW wc; memset(&wc, 0, sizeof(wc)); wc.lpfnWndProc = window_proc; wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); wc.lpszClassName = klass;
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(klass, L"DNS 优选工具", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 720, 500, NULL, NULL, instance, NULL);
    if (!hwnd) { WSACleanup(); return 1; }
    ShowWindow(hwnd, show); UpdateWindow(hwnd);
    MSG msg; while (GetMessageW(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    WSACleanup(); return (int)msg.wParam;
}
