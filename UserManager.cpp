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
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"a, ccs=UTF-8") != 0 || !f) return;
    fwprintf(f, L"WinPE User Manager | image=%ls | user=%ls | dism_exit=%lu\n", imageRoot.c_str(), username.c_str(), result);
    fclose(f);
}

struct WorkerParams { std::wstring imageRoot, xmlPath, username; };
struct WorkerResult { DWORD exitCode = ERROR_GEN_FAILURE; std::wstring output, xmlPath; };

static DWORD WINAPI WorkerThreadProc(LPVOID p) {
    std::unique_ptr<WorkerParams> wp(static_cast<WorkerParams*>(p));
    auto* result = new WorkerResult();
    result->xmlPath = wp->xmlPath;
    result->exitCode = RunDismApplyUnattend(wp->imageRoot, wp->xmlPath, result->output);
    WriteAuditLog(wp->imageRoot, wp->username, result->exitCode);
    WipeString(wp->imageRoot); WipeString(wp->username);
    PostMessageW(GetForegroundWindow(), WM_WORKER_DONE, 0, reinterpret_cast<LPARAM>(result));
    return 0;
}

static void EnableCreateButton(bool enable) { if (g_hCreateBtn) EnableWindow(g_hCreateBtn, enable ? TRUE : FALSE); }

static void SafeGetWindowText(HWND h, std::wstring& out) {
    int len = GetWindowTextLengthW(h); out.assign(static_cast<size_t>(len), L'\0');
    if (len) GetWindowTextW(h, &out[0], len + 1);
}

static void StartCreateUser(HWND hwnd) {
    if (InterlockedCompareExchange(&g_workerRunning, 1, 0) != 0) return;
    int sel = static_cast<int>(SendMessageW(g_hDrives, CB_GETCURSEL, 0, 0));
    if (sel == CB_ERR) { AppendStatusUI(L"Select an installed Windows target first."); InterlockedExchange(&g_workerRunning, 0); return; }
    wchar_t pathBuf[MAX_PATH] = {}; SendMessageW(g_hDrives, CB_GETLBTEXT, sel, reinterpret_cast<LPARAM>(pathBuf));
    std::wstring windowsDir = NormalizeWindowsDirInput(pathBuf);
    if (!IsOfflineWindowsDir(windowsDir)) { AppendStatusUI(L"Selected target is no longer a valid offline Windows installation."); InterlockedExchange(&g_workerRunning, 0); return; }
    std::wstring user, pw, confirm, reason;
    SafeGetWindowText(g_hUsername, user); SafeGetWindowText(g_hPassword, pw); SafeGetWindowText(g_hConfirm, confirm);
    if (!IsValidUsername(user, reason)) { AppendStatusUI(reason); WipeString(pw); WipeString(confirm); InterlockedExchange(&g_workerRunning, 0); return; }
    if (!IsValidPassword(pw, reason)) { AppendStatusUI(reason); WipeString(pw); WipeString(confirm); InterlockedExchange(&g_workerRunning, 0); return; }
    if (pw != confirm) { AppendStatusUI(L"Passwords do not match."); WipeString(pw); WipeString(confirm); InterlockedExchange(&g_workerRunning, 0); return; }
    bool admin = SendMessageW(g_hAdminCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::wstring xml = BuildUnattendXml(user, pw, admin);
    WipeString(pw); WipeString(confirm);
    std::wstring xmlPath;
    if (!CreateUniqueTempFile(xml, xmlPath)) { AppendStatusUI(L"Could not create temporary unattend file."); WipeString(xml); InterlockedExchange(&g_workerRunning, 0); return; }
    WipeString(xml);
    auto* wp = new WorkerParams(); wp->imageRoot = GetImageRootFromSelected(windowsDir); wp->xmlPath = xmlPath; wp->username = user;
    EnableCreateButton(false); AppendStatusUI(L"Applying offline user configuration with DISM...");
    g_hWorkerThread = CreateThread(nullptr, 0, WorkerThreadProc, wp, 0, nullptr);
    if (!g_hWorkerThread) {
        DeleteFileW(xmlPath.c_str()); delete wp; EnableCreateButton(true); InterlockedExchange(&g_workerRunning, 0); AppendStatusUI(L"Failed to start worker thread.");
    }
}

static void OnWorkerDone(LPARAM lp) {
    std::unique_ptr<WorkerResult> result(reinterpret_cast<WorkerResult*>(lp));
    if (g_hWorkerThread) { CloseHandle(g_hWorkerThread); g_hWorkerThread = nullptr; }
    if (!result->output.empty()) AppendStatusUI(result->output, false);
    if (result->exitCode == 0) AppendStatusUI(L"DISM completed successfully. Boot the installed Windows and verify the account.");
    else { std::wstringstream s; s << L"DISM failed with exit code " << result->exitCode << L"."; AppendStatusUI(s.str()); }
    if (!result->xmlPath.empty()) {
        if (DeleteFileW(result->xmlPath.c_str())) WipeString(result->xmlPath);
        else AppendStatusUI(L"Warning: temporary XML could not be deleted; retry cleanup manually.");
    }
    InterlockedExchange(&g_workerRunning, 0); EnableCreateButton(true);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        CreateWindowW(L"STATIC", L"Installed Windows target:", WS_CHILD | WS_VISIBLE, 15, 15, 180, 22, hwnd, nullptr, g_hInst, nullptr);
        g_hDrives = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST, 15, 40, 420, 300, hwnd, reinterpret_cast<HMENU>(IDC_DRIVES), g_hInst, nullptr);
        g_hWinPathStatic = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 15, 75, 500, 22, hwnd, reinterpret_cast<HMENU>(IDC_WINPATH_STATIC), g_hInst, nullptr);
        CreateWindowW(L"STATIC", L"Username:", WS_CHILD | WS_VISIBLE, 15, 110, 100, 22, hwnd, nullptr, g_hInst, nullptr);
        g_hUsername = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP, 120, 108, 300, 24, hwnd, reinterpret_cast<HMENU>(IDC_USERNAME_EDIT), g_hInst, nullptr);
        CreateWindowW(L"STATIC", L"Password:", WS_CHILD | WS_VISIBLE, 15, 145, 100, 22, hwnd, nullptr, g_hInst, nullptr);
        g_hPassword = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD, 120, 143, 300, 24, hwnd, reinterpret_cast<HMENU>(IDC_PASSWORD_EDIT), g_hInst, nullptr);
        CreateWindowW(L"STATIC", L"Confirm:", WS_CHILD | WS_VISIBLE, 15, 180, 100, 22, hwnd, nullptr, g_hInst, nullptr);
        g_hConfirm = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD, 120, 178, 300, 24, hwnd, reinterpret_cast<HMENU>(IDC_CONFIRM_EDIT), g_hInst, nullptr);
        g_hAdminCheck = CreateWindowW(L"BUTTON", L"Add to Administrators", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 120, 213, 220, 24, hwnd, reinterpret_cast<HMENU>(IDC_ADMIN_CHECK), g_hInst, nullptr);
        g_hCreateBtn = CreateWindowW(L"BUTTON", L"Create user", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 120, 248, 140, 30, hwnd, reinterpret_cast<HMENU>(IDC_CREATE_BUTTON), g_hInst, nullptr);
        g_hStatus = CreateWindowW(L"EDIT", L"Ready.\r\n", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 15, 290, 500, 150, hwnd, reinterpret_cast<HMENU>(IDC_STATUS_EDIT), g_hInst, nullptr);
        HWND controls[] = {g_hDrives,g_hWinPathStatic,g_hUsername,g_hPassword,g_hConfirm,g_hAdminCheck,g_hCreateBtn,g_hStatus};
        for (HWND h : controls) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        auto installs = DetectWindowsInstalls();
        for (const auto& p : installs) SendMessageW(g_hDrives, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(p.c_str()));
        if (!installs.empty()) SendMessageW(g_hDrives, CB_SETCURSEL, 0, 0);
        else AppendStatusUI(L"No offline Windows installations detected.");
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_CREATE_BUTTON && HIWORD(wp) == BN_CLICKED) StartCreateUser(hwnd);
        else if (LOWORD(wp) == IDC_DRIVES && HIWORD(wp) == CBN_SELCHANGE) {
            int sel = static_cast<int>(SendMessageW(g_hDrives, CB_GETCURSEL, 0, 0));
            if (sel != CB_ERR) { wchar_t b[MAX_PATH] = {}; SendMessageW(g_hDrives, CB_GETLBTEXT, sel, reinterpret_cast<LPARAM>(b)); SetWindowTextW(g_hWinPathStatic, b); }
        }
        return 0;
    case WM_WORKER_DONE: OnWorkerDone(lp); return 0;
    case WM_CLOSE:
        if (InterlockedCompareExchange(&g_workerRunning, 0, 0) != 0) { MessageBoxW(hwnd, L"Please wait for DISM to finish.", WINDOW_TITLE, MB_OK | MB_ICONINFORMATION); return 0; }
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int RunCliMode(int argc, wchar_t** argv) {
    if (argc < 3) { wprintf(L"Usage: UserManager.exe /cli <WindowsDir> <Username>\n"); return 2; }
    std::wstring windowsDir = NormalizeWindowsDirInput(argv[1]);
    std::wstring username = argv[2];
    if (!IsOfflineWindowsDir(windowsDir)) { wprintf(L"Invalid offline Windows directory.\n"); return 3; }
    std::wstring password, confirm;
    wprintf(L"Password: ");
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE); DWORD oldMode = 0; bool changed = false;
    if (in != INVALID_HANDLE_VALUE && GetConsoleMode(in, &oldMode)) { SetConsoleMode(in, oldMode & ~ENABLE_ECHO_INPUT); changed = true; }
    std::getline(std::wcin, password);
    if (changed) { SetConsoleMode(in, oldMode); wprintf(L"\n"); }
    wprintf(L"Confirm password: ");
    if (in != INVALID_HANDLE_VALUE && GetConsoleMode(in, &oldMode)) { SetConsoleMode(in, oldMode & ~ENABLE_ECHO_INPUT); changed = true; }
    std::getline(std::wcin, confirm);
    if (changed) { SetConsoleMode(in, oldMode); wprintf(L"\n"); }
    std::wstring reason;
    if (!IsValidUsername(username, reason) || !IsValidPassword(password, reason) || password != confirm) {
        if (reason.empty()) reason = L"Passwords do not match.";
        wprintf(L"%ls\n", reason.c_str()); WipeString(password); WipeString(confirm); return 4;
    }
    std::wstring xml = BuildUnattendXml(username, password, false); WipeString(password); WipeString(confirm);
    std::wstring xmlPath;
    if (!CreateUniqueTempFile(xml, xmlPath)) { WipeString(xml); return 5; }
    WipeString(xml);
    std::wstring output; DWORD rc = RunDismApplyUnattend(GetImageRootFromSelected(windowsDir), xmlPath, output);
    wprintf(L"%ls\n", output.c_str());
    if (DeleteFileW(xmlPath.c_str())) WipeString(xmlPath); else wprintf(L"Warning: temporary XML could not be deleted.\n");
    return rc == 0 ? 0 : static_cast<int>(rc);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    g_hInst = hInstance;
    int argc = 0; wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        bool cli = argc >= 2 && _wcsicmp(argv[1], L"/cli") == 0;
        if (cli) { int rc = RunCliMode(argc - 1, argv + 1); LocalFree(argv); return rc; }
        LocalFree(argv);
    }
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES}; InitCommonControlsEx(&icc);
    WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc = WndProc; wc.hInstance = hInstance; wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW); wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION); wc.hIconSm = wc.hIcon;
    if (!RegisterClassExW(&wc)) return 1;
    HWND hwnd = CreateWindowExW(0, CLASS_NAME, WINDOW_TITLE, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT, 550, 500, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    MSG msg{}; while (GetMessageW(&msg, nullptr, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return static_cast<int>(msg.wParam);
}
