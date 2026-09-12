// UserManager.cpp
// WinPE User Manager - native Win32 x64 tool for authorized offline Windows administration.

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <algorithm>
#include <random>
#include <chrono>
#include <cwchar>
#include <cwctype>
#include <cstdio>
#include <iostream>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

static const wchar_t APP_VERSION[] = L"1.0.0";
static const wchar_t CLASS_NAME[] = L"WinPEUserMgrClass";
static const wchar_t WINDOW_TITLE[] = L"WinPE User Manager";
static const UINT WM_WORKER_DONE = WM_APP + 1;

enum {
    IDC_DRIVES = 101,
    IDC_WINPATH_STATIC,
    IDC_USERNAME_EDIT,
    IDC_PASSWORD_EDIT,
    IDC_CONFIRM_EDIT,
    IDC_ADMIN_CHECK,
    IDC_CREATE_BUTTON,
    IDC_STATUS_EDIT
};

static HINSTANCE g_hInst = nullptr;
static HWND g_hCreateBtn = nullptr, g_hDrives = nullptr, g_hWinPathStatic = nullptr;
static HWND g_hUsername = nullptr, g_hPassword = nullptr, g_hConfirm = nullptr;
static HWND g_hAdminCheck = nullptr, g_hStatus = nullptr;
static HANDLE g_hWorkerThread = nullptr;
static volatile LONG g_workerRunning = 0;

static void WipeString(std::wstring& value) {
    if (!value.empty()) {
        SecureZeroMemory(&value[0], value.size() * sizeof(wchar_t));
        value.clear();
    }
}

static void AppendStatusUI(const std::wstring& text, bool newline = true) {
    if (!g_hStatus) return;
    int len = GetWindowTextLengthW(g_hStatus);
    std::wstring cur(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(g_hStatus, &cur[0], len + 1);
    cur.resize(len);
    cur += text;
    if (newline) cur += L"\r\n";
    SetWindowTextW(g_hStatus, cur.c_str());
    SendMessageW(g_hStatus, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(g_hStatus, EM_SCROLLCARET, 0, 0);
}

static std::wstring EscapeXml(const std::wstring& in) {
    std::wstring out;
    out.reserve(in.size() * 2);
    for (wchar_t c : in) {
        switch (c) {
        case L'&': out += L"&amp;"; break;
        case L'<': out += L"&lt;"; break;
        case L'>': out += L"&gt;"; break;
        case L'\'': out += L"&apos;"; break;
        case L'\"': out += L"&quot;"; break;
        default: out += c; break;
        }
    }
    return out;
}

static std::wstring GetCurrentWindowsRoot() {
    wchar_t buf[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(buf, MAX_PATH)) return L"";
    std::wstring s = buf;
    const std::wstring suffix = L"\\Windows";
    if (s.size() >= suffix.size()) {
        std::wstring tail = s.substr(s.size() - suffix.size());
        std::transform(tail.begin(), tail.end(), tail.begin(), towlower);
        std::wstring lowSuffix = suffix;
        std::transform(lowSuffix.begin(), lowSuffix.end(), lowSuffix.begin(), towlower);
        if (tail == lowSuffix) {
            std::wstring root = s.substr(0, s.size() - suffix.size());
            if (root.size() == 2 && root[1] == L':') root += L'\\';
            return root;
        }
    }
    if (s.size() >= 2 && s[1] == L':') return s.substr(0, 2) + L'\\';
    return L"";
}

static bool IsOfflineWindowsDir(const std::wstring& windowsDir) {
    DWORD a = GetFileAttributesW(windowsDir.c_str());
    if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) return false;
    const wchar_t* hives[] = { L"SAM", L"SYSTEM", L"SOFTWARE" };
    for (const wchar_t* hive : hives) {
        std::wstring p = windowsDir + L"\\System32\\config\\" + hive;
        if (GetFileAttributesW(p.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    }
    std::wstring running = GetCurrentWindowsRoot();
    std::wstring n = windowsDir;
    while (!n.empty() && n.back() == L'\\') n.pop_back();
    if (!running.empty()) {
        std::wstring r = running;
        while (!r.empty() && r.back() == L'\\') r.pop_back();
        if (_wcsicmp(n.c_str(), r.c_str()) == 0 || _wcsicmp(n.c_str(), (r + L"\\Windows").c_str()) == 0)
            return false;
    }
    return true;
}

static std::vector<std::wstring> DetectWindowsInstalls() {
    std::vector<std::wstring> result;
    DWORD mask = GetLogicalDrives();
    if (!mask) return result;
    std::wstring current = GetCurrentWindowsRoot();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        wchar_t root[4] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
        std::wstring r = root;
        if (!current.empty() && _wcsicmp(r.c_str(), current.c_str()) == 0) continue;
        std::wstring w = r + L"Windows";
        if (IsOfflineWindowsDir(w)) result.push_back(w);
    }
    return result;
}

static bool IsValidUsername(const std::wstring& name, std::wstring& reason) {
    if (name.empty()) { reason = L"Username must not be empty."; return false; }
    if (name.front() == L' ' || name.back() == L' ') { reason = L"Username cannot start or end with a space."; return false; }
    const wchar_t* bad = L"\\/:*?\"<>|";
    for (wchar_t c : name) {
        if (c < 0x20 || wcschr(bad, c)) { reason = L"Username contains invalid characters."; return false; }
    }
    return true;
}

static bool IsValidPassword(const std::wstring& pw, std::wstring& reason) {
    if (pw.empty()) { reason = L"Password must not be empty."; return false; }
    if (pw.size() < 8) { reason = L"Password must be at least 8 characters."; return false; }
    for (wchar_t c : pw) if (c < 0x20) { reason = L"Password contains control characters."; return false; }
    return true;
}

static std::wstring BuildUnattendXml(const std::wstring& username, const std::wstring& password, bool admin) {
    std::wstringstream s;
    s << L"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
      << L"<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">\r\n"
      << L"  <settings pass=\"offlineServicing\">\r\n"
      << L"    <component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">\r\n"
      << L"      <OfflineUserAccounts>\r\n"
      << L"        <OfflineLocalAccounts>\r\n"
      << L"          <LocalAccount>\r\n"
      << L"            <Password><Value>" << EscapeXml(password) << L"</Value><PlainText>true</PlainText></Password>\r\n";
    if (admin) s << L"            <Group>Administrators</Group>\r\n";
    s << L"            <Name>" << EscapeXml(username) << L"</Name>\r\n"
      << L"          </LocalAccount>\r\n"
      << L"        </OfflineLocalAccounts>\r\n"
      << L"      </OfflineUserAccounts>\r\n"
      << L"    </component>\r\n"
      << L"  </settings>\r\n"
      << L"</unattend>\r\n";
    return s.str();
}

static std::wstring GenerateRandomHex() {
    std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    uint64_t v = rng();
    wchar_t b[32] = {};
    swprintf_s(b, _countof(b), L"%016llx", static_cast<unsigned long long>(v));
    return b;
}

static bool CreateUniqueTempFile(const std::wstring& content, std::wstring& outPath) {
    wchar_t dirBuf[MAX_PATH] = {};
    DWORD n = GetTempPathW(MAX_PATH, dirBuf);
    if (!n || n >= MAX_PATH) return false;
    for (int attempt = 0; attempt < 16; ++attempt) {
        std::wstring path = std::wstring(dirBuf) + L"WinPEUserMgr-" + GenerateRandomHex() + L".xml";
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS) continue;
            return false;
        }
        int bytes = WideCharToMultiByte(CP_UTF8, 0, content.data(), static_cast<int>(content.size()), nullptr, 0, nullptr, nullptr);
        if (bytes <= 0) { CloseHandle(h); DeleteFileW(path.c_str()); return false; }
        std::string utf8(static_cast<size_t>(bytes), '\0');
        if (!WideCharToMultiByte(CP_UTF8, 0, content.data(), static_cast<int>(content.size()), &utf8[0], bytes, nullptr, nullptr)) {
            SecureZeroMemory(&utf8[0], utf8.size()); CloseHandle(h); DeleteFileW(path.c_str()); return false;
        }
        DWORD written = 0;
        BOOL ok = WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        SecureZeroMemory(&utf8[0], utf8.size());
        CloseHandle(h);
        if (!ok || written != static_cast<DWORD>(bytes)) { DeleteFileW(path.c_str()); return false; }
        outPath = path;
        return true;
    }
    return false;
}

static std::wstring NormalizeWindowsDirInput(const std::wstring& input) {
    std::wstring s = input;
    while (!s.empty() && (s.back() == L' ' || s.back() == L'\t' || s.back() == L'\\')) s.pop_back();
    if (s.size() == 2 && s[1] == L':') return s + L"\\Windows";
    if (s.size() >= 7) {
        std::wstring tail = s.substr(s.size() - 7);
        std::transform(tail.begin(), tail.end(), tail.begin(), towlower);
        if (tail == L"windows") return s;
    }
    return s.empty() ? L"" : s + L"\\Windows";
}

static std::wstring GetImageRootFromSelected(const std::wstring& windowsDir) {
    std::wstring s = windowsDir;
    while (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
    if (s.size() >= 7) {
        std::wstring tail = s.substr(s.size() - 7);
        std::transform(tail.begin(), tail.end(), tail.begin(), towlower);
        if (tail == L"windows") {
            std::wstring root = s.substr(0, s.size() - 7);
            while (!root.empty() && (root.back() == L'\\' || root.back() == L'/')) root.pop_back();
            if (root.size() == 2 && root[1] == L':') return root + L'\\';
            if (!root.empty() && root.back() != L'\\') root += L'\\';
            return root;
        }
    }
    if (s.size() >= 2 && s[1] == L':') return s.substr(0, 2) + L'\\';
    return s.empty() ? L"" : s + L'\\';
}

static bool FindDismExe(std::wstring& out) {
    wchar_t sys[MAX_PATH] = {};
    UINT n = GetSystemDirectoryW(sys, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    out = std::wstring(sys) + L"\\dism.exe";
    return GetFileAttributesW(out.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static DWORD RunDismApplyUnattend(const std::wstring& imageRoot, const std::wstring& xmlPath, std::wstring& output) {
    std::wstring dism;
    if (!FindDismExe(dism)) { output = L"DISM executable was not found."; return ERROR_FILE_NOT_FOUND; }
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return GetLastError();
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    std::wstring cmd = L"\"" + dism + L"\" /Image:\"" + imageRoot + L"\" /Apply-Unattend:\"" + xmlPath + L"\"";
    std::vector<wchar_t> cmdLine(cmd.begin(), cmd.end()); cmdLine.push_back(L'\0');
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = writePipe; si.hStdError = writePipe;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(dism.c_str(), cmdLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        DWORD e = GetLastError(); CloseHandle(readPipe); CloseHandle(writePipe); return e;
    }
    CloseHandle(writePipe); writePipe = nullptr;
    char buf[4096]; DWORD got = 0;
    for (;;) {
        BOOL ok = ReadFile(readPipe, buf, sizeof(buf) - 1, &got, nullptr);
        if (!ok || got == 0) break;
        buf[got] = 0;
        int chars = MultiByteToWideChar(GetConsoleOutputCP(), 0, buf, static_cast<int>(got), nullptr, 0);
        if (chars <= 0) chars = MultiByteToWideChar(CP_OEMCP, 0, buf, static_cast<int>(got), nullptr, 0);
        std::wstring w(static_cast<size_t>(chars), L'\0');
        if (chars > 0) MultiByteToWideChar(GetConsoleOutputCP(), 0, buf, static_cast<int>(got), &w[0], chars);
        output += w;
        if (output.size() > 256 * 1024) output.erase(0, output.size() - 256 * 1024);
    }
    CloseHandle(readPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = ERROR_GEN_FAILURE;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return exitCode;
}

static void WriteAuditLog(const std::wstring& imageRoot, const std::wstring& username, DWORD result) {
    wchar_t temp[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, temp)) return;
    std::wstring path = std::wstring(temp) + L"WinPEUserMgr-audit.log";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    wchar_t line[1024] = {};
    swprintf_s(line, _countof(line), L"%04u-%02u-%02u %02u:%02u:%02u | image=%s | user=%s | result=%lu\r\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
               imageRoot.c_str(), username.c_str(), static_cast<unsigned long>(result));
    int bytes = WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
    if (bytes > 1) {
        std::string utf8(static_cast<size_t>(bytes - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, line, -1, &utf8[0], bytes, nullptr, nullptr);
        DWORD written = 0; WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        SecureZeroMemory(&utf8[0], utf8.size());
    }
    CloseHandle(h);
}

static std::wstring ReadOfflineWindowsVersion(const std::wstring& imageRoot) {
    HKEY hKey = nullptr;
    std::wstring keyPath = imageRoot + L"Windows\\System32\\config\\SOFTWARE";
    if (RegLoadKeyW(HKEY_LOCAL_MACHINE, L"WinPEUserMgrTemp", keyPath.c_str()) != ERROR_SUCCESS) return L"";
    std::wstring result;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"WinPEUserMgrTemp\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t product[256] = {}; DWORD type = 0, cb = sizeof(product);
        if (RegQueryValueExW(hKey, L"ProductName", nullptr, &type, reinterpret_cast<BYTE*>(product), &cb) == ERROR_SUCCESS && type == REG_SZ) result = product;
        RegCloseKey(hKey);
    }
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"WinPEUserMgrTemp");
    return result;
}

static void SafePostMessage(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    if (hwnd) PostMessageW(hwnd, msg, w, l);
}

struct WorkerParams {
    HWND hwnd = nullptr;
    std::wstring imageRoot;
    std::wstring username;
    std::wstring password;
    bool admin = false;
    std::wstring tempUnattendPath;
};

struct WorkerResult {
    DWORD result = ERROR_GEN_FAILURE;
    std::wstring output;
    std::wstring tempUnattendPath;
};

static DWORD WINAPI WorkerThreadProc(LPVOID p) {
    std::unique_ptr<WorkerParams> params(static_cast<WorkerParams*>(p));
    std::unique_ptr<WorkerResult> res(new WorkerResult);
    res->tempUnattendPath = params->tempUnattendPath;
    std::wstring xml = BuildUnattendXml(params->username, params->password, params->admin);
    WipeString(params->password);
    if (!CreateUniqueTempFile(xml, res->tempUnattendPath)) {
        res->result = GetLastError();
        WipeString(xml);
        SafePostMessage(params->hwnd, WM_WORKER_DONE, 0, reinterpret_cast<LPARAM>(res.release()));
        return 0;
    }
    WipeString(xml);
    res->result = RunDismApplyUnattend(params->imageRoot, res->tempUnattendPath, res->output);
    WriteAuditLog(params->imageRoot, params->username, res->result);
    if (DeleteFileW(res->tempUnattendPath.c_str())) {
        WipeString(res->tempUnattendPath);
    }
    SafePostMessage(params->hwnd, WM_WORKER_DONE, 0, reinterpret_cast<LPARAM>(res.release()));
    return 0;
}

static std::wstring SafeGetWindowText(HWND h) {
    int len = GetWindowTextLengthW(h);
    std::wstring s(static_cast<size_t>(len) + 1, L'\0');
    if (len > 0) GetWindowTextW(h, &s[0], len + 1);
    s.resize(len);
    return s;
}

static void StartCreateUser(HWND hwnd) {
    if (InterlockedCompareExchange(&g_workerRunning, 1, 0) != 0) return;
    int idx = static_cast<int>(SendMessageW(g_hDrives, CB_GETCURSEL, 0, 0));
    if (idx == CB_ERR) { AppendStatusUI(L"Select an installed Windows drive first."); InterlockedExchange(&g_workerRunning, 0); return; }
    wchar_t buf[1024] = {}; SendMessageW(g_hDrives, CB_GETLBTEXT, idx, reinterpret_cast<LPARAM>(buf));
    std::wstring windowsDir = NormalizeWindowsDirInput(buf);
    if (!IsOfflineWindowsDir(windowsDir)) { AppendStatusUI(L"Selected Windows directory is no longer a valid offline Windows image."); InterlockedExchange(&g_workerRunning, 0); return; }
    std::wstring imageRoot = GetImageRootFromSelected(windowsDir);
    std::wstring username = SafeGetWindowText(g_hUsername);
    std::wstring password = SafeGetWindowText(g_hPassword);
    std::wstring confirm = SafeGetWindowText(g_hConfirm);
    std::wstring reason;
    if (!IsValidUsername(username, reason)) { AppendStatusUI(reason); WipeString(password); WipeString(confirm); InterlockedExchange(&g_workerRunning, 0); return; }
    if (!IsValidPassword(password, reason)) { AppendStatusUI(reason); WipeString(password); WipeString(confirm); InterlockedExchange(&g_workerRunning, 0); return; }
    if (password != confirm) { AppendStatusUI(L"Passwords do not match."); WipeString(password); WipeString(confirm); InterlockedExchange(&g_workerRunning, 0); return; }
    WipeString(confirm);
    bool admin = SendMessageW(g_hAdminCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
    auto params = new WorkerParams;
    params->hwnd = hwnd; params->imageRoot = imageRoot; params->username = username; params->password = password; params->admin = admin;
    WipeString(password);
    EnableWindow(g_hCreateBtn, FALSE);
    AppendStatusUI(L"Applying offline user configuration with DISM...");
    g_hWorkerThread = CreateThread(nullptr, 0, WorkerThreadProc, params, 0, nullptr);
    if (!g_hWorkerThread) {
        DWORD e = GetLastError(); delete params; InterlockedExchange(&g_workerRunning, 0); EnableWindow(g_hCreateBtn, TRUE);
        AppendStatusUI(L"Could not start worker thread. Error " + std::to_wstring(e));
    }
}

static void OnWorkerDone(HWND hwnd, WorkerResult* res) {
    if (!res) { InterlockedExchange(&g_workerRunning, 0); EnableWindow(g_hCreateBtn, TRUE); return; }
    if (!res->output.empty()) AppendStatusUI(res->output, false);
    if (!res->tempUnattendPath.empty()) AppendStatusUI(L"Temporary unattend file could not be deleted: " + res->tempUnattendPath);
    if (res->result == 0) AppendStatusUI(L"DISM completed successfully. Boot the installed Windows and verify the account.");
    else AppendStatusUI(L"DISM failed. Exit code: " + std::to_wstring(res->result));
    WipeString(res->tempUnattendPath); delete res;
    if (g_hWorkerThread) { CloseHandle(g_hWorkerThread); g_hWorkerThread = nullptr; }
    InterlockedExchange(&g_workerRunning, 0); EnableWindow(g_hCreateBtn, TRUE);
    (void)hwnd;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hDrives = CreateWindowW(L"COMBOBOX", nullptr, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                                  20, 20, 420, 500, hwnd, reinterpret_cast<HMENU>(IDC_DRIVES), g_hInst, nullptr);
        g_hWinPathStatic = CreateWindowW(L"STATIC", L"No offline Windows image selected.", WS_CHILD | WS_VISIBLE,
                                         20, 55, 620, 25, hwnd, reinterpret_cast<HMENU>(IDC_WINPATH_STATIC), g_hInst, nullptr);
        CreateWindowW(L"STATIC", L"Username:", WS_CHILD | WS_VISIBLE, 20, 95, 100, 22, hwnd, nullptr, g_hInst, nullptr);
        g_hUsername = CreateWindowW(L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER, 130, 92, 310, 26, hwnd, reinterpret_cast<HMENU>(IDC_USERNAME_EDIT), g_hInst, nullptr);
        CreateWindowW(L"STATIC", L"Password:", WS_CHILD | WS_VISIBLE, 20, 135, 100, 22, hwnd, nullptr, g_hInst, nullptr);
        g_hPassword = CreateWindowW(L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD, 130, 132, 310, 26, hwnd, reinterpret_cast<HMENU>(IDC_PASSWORD_EDIT), g_hInst, nullptr);
        CreateWindowW(L"STATIC", L"Confirm:", WS_CHILD | WS_VISIBLE, 20, 175, 100, 22, hwnd, nullptr, g_hInst, nullptr);
        g_hConfirm = CreateWindowW(L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD, 130, 172, 310, 26, hwnd, reinterpret_cast<HMENU>(IDC_CONFIRM_EDIT), g_hInst, nullptr);
        g_hAdminCheck = CreateWindowW(L"BUTTON", L"Add to Administrators", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                      130, 212, 220, 25, hwnd, reinterpret_cast<HMENU>(IDC_ADMIN_CHECK), g_hInst, nullptr);
        g_hCreateBtn = CreateWindowW(L"BUTTON", L"Create offline user", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                     20, 255, 200, 32, hwnd, reinterpret_cast<HMENU>(IDC_CREATE_BUTTON), g_hInst, nullptr);
        g_hStatus = CreateWindowW(L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                  20, 305, 620, 220, hwnd, reinterpret_cast<HMENU>(IDC_STATUS_EDIT), g_hInst, nullptr);
        auto installs = DetectWindowsInstalls();
        for (const auto& p : installs) SendMessageW(g_hDrives, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(p.c_str()));
        if (!installs.empty()) {
            SendMessageW(g_hDrives, CB_SETCURSEL, 0, 0);
            SetWindowTextW(g_hWinPathStatic, installs[0].c_str());
        }
        AppendStatusUI(installs.empty() ? L"No offline Windows installations detected." : L"Select the target Windows installation.");
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CREATE_BUTTON && HIWORD(wParam) == BN_CLICKED) StartCreateUser(hwnd);
        else if (LOWORD(wParam) == IDC_DRIVES && HIWORD(wParam) == CBN_SELCHANGE) {
            int idx = static_cast<int>(SendMessageW(g_hDrives, CB_GETCURSEL, 0, 0));
            if (idx != CB_ERR) { wchar_t b[1024] = {}; SendMessageW(g_hDrives, CB_GETLBTEXT, idx, reinterpret_cast<LPARAM>(b)); SetWindowTextW(g_hWinPathStatic, b); }
        }
        break;
    case WM_CLOSE:
        if (g_workerRunning) { AppendStatusUI(L"Operation is still running; wait for DISM to finish."); return 0; }
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        PostQuitMessage(0); return 0;
    case WM_WORKER_DONE:
        OnWorkerDone(hwnd, reinterpret_cast<WorkerResult*>(lParam)); return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static int RunCliMode() {
    auto installs = DetectWindowsInstalls();
    if (installs.empty()) { wprintf(L"No offline Windows installations detected.\n"); return 1; }
    wprintf(L"Offline Windows installations:\n");
    for (size_t i = 0; i < installs.size(); ++i) wprintf(L"  %zu: %s\n", i + 1, installs[i].c_str());
    wprintf(L"Select: ");
    size_t sel = 0; if (!(std::wcin >> sel) || sel < 1 || sel > installs.size()) return 1;
    std::wstring username, password, confirm;
    wprintf(L"Username: "); std::wcin >> username;
    wprintf(L"Password: ");
    std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
    std::getline(std::wcin, password);
    wprintf(L"Confirm password: ");
    std::getline(std::wcin, confirm);
    std::wstring reason;
    if (!IsValidUsername(username, reason) || !IsValidPassword(password, reason) || password != confirm) {
        wprintf(L"Invalid input: %s\n", reason.c_str()); WipeString(password); WipeString(confirm); return 1;
    }
    WipeString(confirm);
    std::wstring xml = BuildUnattendXml(username, password, false); WipeString(password);
    std::wstring temp;
    if (!CreateUniqueTempFile(xml, temp)) { WipeString(xml); return 1; }
    WipeString(xml);
    std::wstring output;
    DWORD rc = RunDismApplyUnattend(GetImageRootFromSelected(installs[sel - 1]), temp, output);
    if (!DeleteFileW(temp.c_str())) wprintf(L"Warning: temporary file remains: %s\n", temp.c_str());
    WipeString(temp);
    wprintf(L"%s\n", output.c_str());
    return rc == 0 ? 0 : 1;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    g_hInst = hInstance;
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES }; InitCommonControlsEx(&icc);
    int argc = 0; LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool cli = false; for (int i = 1; argv && i < argc; ++i) if (_wcsicmp(argv[i], L"/cli") == 0) cli = true;
    if (argv) LocalFree(argv);
    if (cli) return RunCliMode();
    WNDCLASSW wc{}; wc.lpfnWndProc = WndProc; wc.hInstance = hInstance; wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW); wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassW(&wc)) return 1;
    HWND hwnd = CreateWindowW(CLASS_NAME, WINDOW_TITLE, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                              CW_USEDEFAULT, CW_USEDEFAULT, 680, 590, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    MSG msg{}; while (GetMessageW(&msg, nullptr, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return static_cast<int>(msg.wParam);
}
