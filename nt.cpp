#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "ntdll.lib")

// Trusted modules list
std::vector<std::wstring> trustedModules = {
    L"kernel32.dll",
    L"user32.dll",
    // Add other trusted modules here
};

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

typedef struct _SYSTEM_MODULE {
    ULONG                   Reserved[2];
    PVOID                   Base;
    ULONG                   Size;
    ULONG                   Flags;
    USHORT                  Index;
    USHORT                  Unknown;
    USHORT                  LoadCount;
    USHORT                  ModuleNameOffset;
    CHAR                    ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG                   ModulesCount;
    SYSTEM_MODULE           Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

bool IsModuleTrusted(const std::wstring& moduleName) {
    for (const auto& trustedModule : trustedModules) {
        if (_wcsicmp(moduleName.c_str(), trustedModule.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

std::wstring GetModuleNameFromAddress(LPVOID addr, PSYSTEM_MODULE_INFORMATION pModuleInfo) {
    for (ULONG i = 0; i < pModuleInfo->ModulesCount; i++) {
        PVOID moduleBase = pModuleInfo->Modules[i].Base;
        ULONG moduleSize = pModuleInfo->Modules[i].Size;

        if (addr >= moduleBase && addr < (PVOID)((char*)moduleBase + moduleSize)) {
            CHAR* imageName = pModuleInfo->Modules[i].ImageName;
            std::wstring moduleName(imageName + pModuleInfo->Modules[i].ModuleNameOffset);
            return moduleName;
        }
    }
    return L"";
}

void CheckHooks() {
    HHOOK hHook = NULL;
    int hookTypes[] = { WH_KEYBOARD_LL, WH_MOUSE_LL };

    // Load NtQuerySystemInformation dynamically
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    ULONG size = 0;
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);

    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(size);
    if (pModuleInfo == NULL) {
        std::wcerr << L"Failed to allocate memory for module information" << std::endl;
        return;
    }

    if (NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, size, &size) != 0) {
        std::wcerr << L"NtQuerySystemInformation failed" << std::endl;
        free(pModuleInfo);
        return;
    }

    for (int hookType : hookTypes) {
        hHook = SetWindowsHookEx(hookType, NULL, NULL, 0);
        if (hHook) {
            HOOKPROC hookProc = (HOOKPROC)GetWindowLongPtr((HWND)hHook, GWLP_WNDPROC);
            if (hookProc) {
                std::wstring moduleName = GetModuleNameFromAddress((LPVOID)hookProc, pModuleInfo);
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

    free(pModuleInfo);
}

int main() {
    CheckHooks();
    return 0;
}
