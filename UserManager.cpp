// UserManager.cpp
//
// WinPE User Manager - native Win32 C++ (Unicode) GUI application
// Creates a local user in an offline installed Windows using an Unattend.xml
// applied with DISM: dism.exe /Image:<offline-root> /Apply-Unattend:<file>
//
// Build suggestion (x64 Native Tools prompt):
// cl /EHsc /W4 /DUNICODE /D_UNICODE /MT /O2 UserManager.cpp /link /SUBSYSTEM:WINDOWS /MACHINE:X64 /OUT:UserManager.exe

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>   // CommandLineToArgvW
#include <iostream>     // std::wcout / std::wcin (CLI)
#include <cstdio>       // freopen_s
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <algorithm>
#include <random>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <cwctype>      // towlower

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

// Application version
static const wchar_t APP_VERSION[] = L"1.0.0";

// Control IDs
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

static const wchar_t CLASS_NAME[] = L"WinPEUserMgrClass";
static const wchar_t WINDOW_TITLE[] = L"WinPE User Manager";

HINSTANCE g_hInst = nullptr;

// UI handles
static HWND g_hCreateBtn = nullptr;
static HWND g_hDrives = nullptr;
static HWND g_hWinPathStatic = nullptr;
static HWND g_hUsername = nullptr;
static HWND g_hPassword = nullptr;
static HWND g_hConfirm = nullptr;
static HWND g_hAdminCheck = nullptr;
static HWND g_hStatus = nullptr;

// Worker/process synchronization (no global DISM handle or CRITICAL_SECTION needed)
// Worker thread handle and running flag:
static HANDLE g_hWorkerThread = nullptr;
static volatile LONG g_workerRunning = 0; // 0 = idle, 1 = running

// Custom message posted when worker completed (WPARAM = WorkerResult*)
static const UINT WM_WORKER_DONE = WM_APP + 1;

// Helper: wipe std::wstring content securely (best-effort)
static void WipeString(std::wstring &value)
{
    if (!value.empty()) {
        SecureZeroMemory(&value[0], value.size() * sizeof(wchar_t));
        value.clear();
    }
}

// Append text to status control (UI thread)
static void AppendStatusUI(const std::wstring &text, bool newline = true)
{
    if (!g_hStatus) return;
    int len = GetWindowTextLengthW(g_hStatus);
    std::wstring cur;
    cur.resize(len + 1);
    GetWindowTextW(g_hStatus, &cur[0], len + 1);
    cur.resize(len);
    std::wstring out = cur + text + (newline ? L"\r\n" : L"");
    SetWindowTextW(g_hStatus, out.c_str());
}

// XML escape
static std::wstring EscapeXml(const std::wstring &in)
{
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

// Return running Windows root (e.g., "X:\\") to exclude WinPE runtime
static std::wstring GetCurrentWindowsRoot()
{
    wchar_t buf[MAX_PATH] = {};
    if (GetWindowsDirectoryW(buf, MAX_PATH) == 0) return L"";
    std::wstring s = buf; // like "X:\\Windows"
    std::wstring suffix = L"\\Windows";
    if (s.size() >= suffix.size()) {
        std::wstring tail = s.substr(s.size() - suffix.size());
        std::transform(tail.begin(), tail.end(), tail.begin(), towlower);
        std::wstring lowerSuffix = suffix; std::transform(lowerSuffix.begin(), lowerSuffix.end(), lowerSuffix.begin(), towlower);
        if (tail == lowerSuffix) {
            std::wstring root = s.substr(0, s.size() - suffix.size());
            if (root.size() == 2 && root[1] == L':') root += L'\\';
            return root;
        }
    }
    if (s.size() >= 2 && s[1] == L':') return s.substr(0, 2) + L'\\';
    return L"";
}

// Detect installed Windows systems (drive-letter based) and exclude running WinPE
static std::vector<std::wstring> DetectWindowsInstalls()
{
    std::vector<std::wstring> results;
    std::wstring currentRoot = GetCurrentWindowsRoot();
    DWORD mask = GetLogicalDrives();
    if (mask == 0) return results;
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1 << i))) continue;
        wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
        std::wstring rootStr = root;
        if (!currentRoot.empty() && _wcsicmp(rootStr.c_str(), currentRoot.c_str()) == 0) continue;
        std::wstring winDir = rootStr + L"Windows";
        DWORD a = GetFileAttributesW(winDir.c_str());
        if (a == INVALID_FILE_ATTRIBUTES) continue;
        if (!(a & FILE_ATTRIBUTE_DIRECTORY)) continue;
        // Check hive files
        std::wstring sam = winDir + L"\\System32\\config\\SAM";
        std::wstring system = winDir + L"\\System32\\config\\SYSTEM";
        std::wstring software = winDir + L"\\System32\\config\\SOFTWARE";
        if (GetFileAttributesW(sam.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        if (GetFileAttributesW(system.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        if (GetFileAttributesW(software.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        results.push_back(winDir);
    }
    return results;
}

static void EnableCreateButton(bool enable)
{
    if (g_hCreateBtn) EnableWindow(g_hCreateBtn, enable ? TRUE : FALSE);
}

// Validation (application policy)
static bool IsValidUsername(const std::wstring &name, std::wstring &reason)
{
    if (name.empty()) { reason = L"Username must not be empty."; return false; }
    if (name.front() == L' ' || name.back() == L' ') { reason = L"Username cannot start or end with a space."; return false; }
    const wchar_t *bad = L"\\/:*?\"<>|";
    for (wchar_t c : name) {
        if (c < 0x20) { reason = L"Username contains control characters."; return false; }
        if (wcschr(bad, c)) { reason = L"Username contains invalid characters (\\ / : * ? \" < > |)."; return false; }
    }
    return true;
}

static bool IsValidPassword(const std::wstring &pw, std::wstring &reason)
{
    if (pw.empty()) { reason = L"Password must not be empty."; return false; }
    if (pw.size() < 8) { reason = L"Password must be at least 8 characters (application validation policy)."; return false; }
    for (wchar_t c : pw) {
        if (c < 0x20) { reason = L"Password contains control characters."; return false; }
    }
    return true;
}

// Build Unattend XML using Microsoft-Windows-Shell-Setup -> OfflineUserAccounts -> OfflineLocalAccounts -> LocalAccount
static std::wstring BuildUnattendXml(const std::wstring &username, const std::wstring &password, bool addToAdmin)
{
    std::wstring userEsc = EscapeXml(username);
    std::wstring pwEsc = EscapeXml(password);
    std::wstringstream ss;
    ss << L"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n";
    ss << L"<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">\r\n";
    ss << L"  <settings pass=\"offlineServicing\">\r\n";
    ss << L"    <component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">\r\n";
    ss << L"      <OfflineUserAccounts>\r\n";
    ss << L"        <OfflineLocalAccounts>\r\n";
    ss << L"          <LocalAccount>\r\n";
    ss << L"            <Password>\r\n";
    ss << L"              <Value>" << pwEsc << L"</Value>\r\n";
    ss << L"              <PlainText>true</PlainText>\r\n";
    ss << L"            </Password>\r\n";
    if (addToAdmin) ss << L"            <Group>Administrators</Group>\r\n";
    ss << L"            <Name>" << userEsc << L"</Name>\r\n";
    ss << L"          </LocalAccount>\r\n";
    ss << L"        </OfflineLocalAccounts>\r\n";
    ss << L"      </OfflineUserAccounts>\r\n";
    ss << L"    </component>\r\n";
    ss << L"  </settings>\r\n";
    ss << L"</unattend>\r\n";
    return ss.str();
}

// Random hex suffix generator (not claimed cryptographically secure)
static std::wstring GenerateRandomHex()
{
    std::mt19937_64 rng((uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t v = dist(rng);
    wchar_t buf[32];
    swprintf_s(buf, _countof(buf), L"%016llx", (unsigned long long)v);
    return std::wstring(buf);
}

// Create a unique temporary file (CREATE_NEW), write UTF-8 content, close file, return full path in outPath.
static bool CreateUniqueTempFile(const std::wstring &content, std::wstring &outPath)
{
    wchar_t tempDirBuf[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tempDirBuf) || !*tempDirBuf) return false;
    std::wstring tempDir = tempDirBuf;
    for (int attempt = 0; attempt < 16; ++attempt) {
        std::wstring name = L"WinPEUserMgr-" + GenerateRandomHex() + L".xml";
        std::wstring full = tempDir + name;
        HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) { Sleep(5); continue; }
            return false;
        }
        int cb = WideCharToMultiByte(CP_UTF8, 0, content.data(), (int)content.size(), nullptr, 0, nullptr, nullptr);
        if (cb == 0) { CloseHandle(h); DeleteFileW(full.c_str()); return false; }
        std::string utf8; utf8.resize(cb);
        int rc = WideCharToMultiByte(CP_UTF8, 0, content.data(), (int)content.size(), &utf8[0], cb, nullptr, nullptr);
        if (rc == 0) { CloseHandle(h); DeleteFileW(full.c_str()); return false; }
        DWORD written = 0;
        BOOL ok = WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
        SecureZeroMemory(&utf8[0], utf8.size());
        CloseHandle(h);
        if (!ok || written != utf8.size()) { DeleteFileW(full.c_str()); return false; }
        outPath = full;
        return true;
    }
    return false;
}

// Normalize windows dir input provided by user (CLI) and avoid adding duplicate "\\Windows"
static std::wstring NormalizeWindowsDirInput(const std::wstring &input)
{
    if (input.empty()) return L"";
    std::wstring s = input;
    // trim trailing spaces
    while (!s.empty() && (s.back() == L' ' || s.back() == L'\t')) s.pop_back();
    // remove trailing backslashes
    while (!s.empty() && s.back() == L'\\') s.pop_back();
    // if input is like "D:" => treat as "D:\\Windows"
    if (s.size() == 2 && s[1] == L':') {
        return s + L"\\Windows";
    }
    // if already ends with "Windows" (case-insensitive), return as-is
    if (s.size() >= 7) {
        std::wstring tail = s.substr(s.size() - 7);
        std::wstring tailLower = tail; std::transform(tailLower.begin(), tailLower.end(), tailLower.begin(), towlower);
        if (tailLower == L"windows") {
            return s;
        }
    }
    // else append "\\Windows"
    return s + L"\\Windows";
}

// Validate offline windows dir (used by GUI & CLI)
static bool ValidateOfflineWindowsDir(const std::wstring &windowsDir)
{
    if (windowsDir.empty()) return false;
    DWORD attr = GetFileAttributesW(windowsDir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) return false;
    std::wstring sam = windowsDir + L"\\System32\\config\\SAM";
    std::wstring system = windowsDir + L"\\System32\\config\\SYSTEM";
    std::wstring software = windowsDir + L"\\System32\\config\\SOFTWARE";
    if (GetFileAttributesW(sam.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    if (GetFileAttributesW(system.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    if (GetFileAttributesW(software.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    // exclude running WinPE root
    std::wstring runningRoot = GetCurrentWindowsRoot();
    if (!runningRoot.empty()) {
        std::wstring rr = runningRoot;
        if (rr.back() == L'\\') rr.pop_back();
        std::wstring normalized = windowsDir;
        if (!normalized.empty() && normalized.back() == L'\\') normalized.pop_back();
        // compare rr and normalized (allow normalized being rr or rr\\Windows)
        if (_wcsicmp(normalized.c_str(), rr.c_str()) == 0) return false;
        std::wstring rrWin = rr + L"\\Windows";
        if (_wcsicmp(normalized.c_str(), rrWin.c_str()) == 0) return false;
    }
    return true;
}

// Get image root from selected windows dir: "D:\\Windows" => "D:\\"
static std::wstring GetImageRootFromSelected(const std::wstring& windowsDir)
{
    if (windowsDir.empty()) return L"";
    std::wstring s = windowsDir;
    // Remove trailing backslashes
    while (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
    // If it ends with "\\Windows" (case-insensitive), remove that suffix
    if (s.size() >= 7) {
        std::wstring tail = s.substr(s.size() - 7);
        std::wstring tailLower = tail; std::transform(tailLower.begin(), tailLower.end(), tailLower.begin(), towlower);
        if (tailLower == L"windows") {
            std::wstring root = s.substr(0, s.size() - 7);
            // If root ends with backslash, trim it
            while (!root.empty() && (root.back() == L'\\' || root.back() == L'/')) root.pop_back();
            // If root is like "D:" convert to "D:\\"
            if (root.size() == 2 && root[1] == L':') return root + L'\\';
            // If root already contains a path, return with trailing backslash
            if (!root.empty() && root.back() != L'\\') root += L'\\';
            return root;
        }
    }
    // If input looks like "D:" or "D:\\", return "D:\\"
    if (s.size() >= 2 && s[1] == L':') {
        std::wstring root = s.substr(0, 2);
        return root + L'\\';
    }
    // As a fallback, ensure trailing backslash
    if (s.back() != L'\\') return s + L'\\';
    return s;
}

// --- DISM invocation + worker implementation ---

struct WorkerResult {
    int exitCode;
    std::wstring output; // captured stdout+stderr (converted to UTF-16)
    std::wstring unattendPath;
    bool success;
    std::wstring error;
};

// Convert a narrow buffer to wide using UTF-8 with fallback to ANSI
static std::wstring ConvertToWideWithFallback(const std::string &bytes)
{
    if (bytes.empty()) return L"";
    int needed = MultiByteToWideChar(CP_UTF8, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
    if (needed > 0) {
        std::wstring out; out.resize(needed);
        MultiByteToWideChar(CP_UTF8, 0, bytes.data(), (int)bytes.size(), &out[0], needed);
        return out;
    }
    // fallback to ANSI
    needed = MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
    if (needed > 0) {
        std::wstring out; out.resize(needed);
        MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), &out[0], needed);
        return out;
    }
    return L"";
}

// Run a process and capture combined stdout+stderr into a string. Returns exit code in outExit.
static bool RunProcessCaptureOutput(const std::wstring &commandLine, int &outExit, std::string &outText, std::wstring &error)
{
    outExit = -1;
    outText.clear();
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        error = L"CreatePipe failed";
        return false;
    }
    // Ensure read handle is not inherited
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = nullptr;

    // Create mutable command buffer
    std::vector<wchar_t> cmd; cmd.assign(commandLine.begin(), commandLine.end()); cmd.push_back(0);

    BOOL created = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    // Close the write end in parent after process created (or if failed)
    CloseHandle(hWrite);
    if (!created) {
        DWORD e = GetLastError();
        wchar_t buf[128]; swprintf_s(buf, L"CreateProcessW failed: %u", e);
        error = buf;
        CloseHandle(hRead);
        return false;
    }

    // Read output until process ends
    const DWORD BUFSIZE = 4096;
    char buffer[BUFSIZE];
    DWORD read = 0;
    std::string accum;
    for (;;) {
        BOOL ok = ReadFile(hRead, buffer, BUFSIZE, &read, nullptr);
        if (read > 0) accum.append(buffer, buffer + read);
        if (!ok) break;
    }
    // Wait for process
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0; GetExitCodeProcess(pi.hProcess, &exitCode);
    outExit = (int)exitCode;

    // Cleanup
    CloseHandle(hRead);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    outText.swap(accum);
    return true;
}

// Worker thread: creates unattend xml file, invokes DISM with /Image:<imageRoot> /Apply-Unattend:<file>
static DWORD WINAPI WorkerThreadProc(LPVOID param)
{
    // param expected to be a heap-allocated array of three std::wstring* values:
    // [0] = selectedWindowsDir, [1] = username, [2] = password
    std::wstring *arr = reinterpret_cast<std::wstring*>(param);
    std::wstring selectedWindows = arr[0];
    std::wstring username = arr[1];
    std::wstring password = arr[2];
    bool addToAdmin = false; // TODO: pass flag if needed; for now assume unchecked

    // wipe the heap array container asap
    // (we'll still need username/password values stored above)
    // free the param memory
    delete[] arr;

    WorkerResult *res = new WorkerResult();
    res->exitCode = -1; res->success = false; res->output.clear(); res->unattendPath.clear(); res->error.clear();

    // Build unattend xml
    std::wstring xml = BuildUnattendXml(username, password, addToAdmin);
    std::wstring unattendPath;
    if (!CreateUniqueTempFile(xml, unattendPath)) {
        res->error = L"Failed to create temporary unattend file.";
        PostMessage(GetActiveWindow(), WM_WORKER_DONE, (WPARAM)res, 0);
        WipeString(username); WipeString(password);
        return 0;
    }
    res->unattendPath = unattendPath;

    // Determine image root from selected Windows dir
    std::wstring imageRoot = GetImageRootFromSelected(selectedWindows);
    if (imageRoot.empty()) {
        res->error = L"Failed to determine image root from selected Windows directory.";
        // attempt cleanup
        DeleteFileW(unattendPath.c_str());
        PostMessage(GetActiveWindow(), WM_WORKER_DONE, (WPARAM)res, 0);
        WipeString(username); WipeString(password);
        return 0;
    }

    // Validate that the image path exists
    DWORD attr = GetFileAttributesW(imageRoot.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        res->error = L"Image root does not exist or is inaccessible: " + imageRoot;
        DeleteFileW(unattendPath.c_str());
        PostMessage(GetActiveWindow(), WM_WORKER_DONE, (WPARAM)res, 0);
        WipeString(username); WipeString(password);
        return 0;
    }

    // Build command line: dism.exe /Image:"D:\" /Apply-Unattend:"C:\path\file.xml"
    std::wstring cmd = L"dism.exe ";
    cmd += L"/Image:\"" + imageRoot + L"\" ";
    cmd += L"/Apply-Unattend:\"" + unattendPath + L"\"";

    std::string rawOut;
    int exitCode = -1;
    std::wstring runErr;
    bool ok = RunProcessCaptureOutput(cmd, exitCode, rawOut, runErr);
    if (!ok) {
        res->error = L"Failed to run DISM: " + runErr;
        // clean up unattend
        DeleteFileW(unattendPath.c_str());
        PostMessage(GetActiveWindow(), WM_WORKER_DONE, (WPARAM)res, 0);
        WipeString(username); WipeString(password);
        return 0;
    }

    res->exitCode = exitCode;
    res->output = ConvertToWideWithFallback(rawOut);
    res->success = (exitCode == 0);

    // Try to delete unattend file (best-effort)
    DeleteFileW(unattendPath.c_str());

    // Wipe sensitive strings
    WipeString(username); WipeString(password);

    // Post result to UI thread
    PostMessage(GetActiveWindow(), WM_WORKER_DONE, (WPARAM)res, 0);
    return 0;
}

// Kick off the worker: allocate param array and create thread
static bool StartWorkerForApply(const std::wstring &selectedWindows, const std::wstring &username, const std::wstring &password, bool addToAdmin)
{
    if (InterlockedCompareExchange(&g_workerRunning, 1, 0) != 0) return false; // already running
    // allocate array
    std::wstring *arr = new std::wstring[3];
    arr[0] = selectedWindows; arr[1] = username; arr[2] = password;
    // create thread
    DWORD tid = 0;
    g_hWorkerThread = CreateThread(nullptr, 0, WorkerThreadProc, arr, 0, &tid);
    if (!g_hWorkerThread) {
        delete[] arr; InterlockedExchange(&g_workerRunning, 0); return false;
    }
    return true;
}

// The rest of the GUI/CLI code would call StartWorkerForApply(selectedWindows, username, password, adminFlag)

// (UI message handling must process WM_WORKER_DONE and free WorkerResult*)

