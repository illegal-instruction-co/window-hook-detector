#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <string>
 
std::vector<std::wstring> trustedModules = {
    L"kernel32.dll",
    L"user32.dll",
    // Add other trusted modules
};
 
bool IsModuleTrusted(const std::wstring& moduleName) {
    for (const auto& trustedModule : trustedModules) {
        if (_wcsicmp(moduleName.c_str(), trustedModule.c_str()) == 0) {
            return true;
        }
    }
    return false;
}
 
std::wstring GetModuleNameFromAddress(LPVOID addr) {
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    TCHAR szModName[MAX_PATH];
 
    DWORD pid = GetCurrentProcessId();
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return L"";
    }
 
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo));
            if (addr >= modInfo.lpBaseOfDll && addr < (LPVOID)((char*)modInfo.lpBaseOfDll + modInfo.SizeOfImage)) {
                if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                    CloseHandle(hProcess);
                    return szModName;
                }
            }
        }
    }
    CloseHandle(hProcess);
    return L"";
}
 
void CheckHooks() {
    HHOOK hHook = NULL;
    int hookTypes[] = { WH_KEYBOARD_LL, WH_MOUSE_LL };
 
    for (int hookType : hookTypes) {
        hHook = SetWindowsHookEx(hookType, NULL, NULL, 0);
        if (hHook) {
            HOOKPROC hookProc = (HOOKPROC)GetWindowLongPtr((HWND)hHook, GWLP_WNDPROC);
            if (hookProc) {
                std::wstring moduleName = GetModuleNameFromAddress((LPVOID)hookProc);
                if (!moduleName.empty()) {
                    if (IsModuleTrusted(moduleName)) {
                        std::wcout << L"Hook in trusted module: " << moduleName << std::endl;
                    } else {
                        std::wcout << L"Hook in untrusted module: " << moduleName << std::endl;
                    }
                }
            }
            UnhookWindowsHookEx(hHook);
        }
    }
}
 
int main() {
    CheckHooks();
    return 0;
}
