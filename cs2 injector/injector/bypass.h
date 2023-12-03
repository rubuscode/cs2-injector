#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <stdexcept>
#include <filesystem>


class Injector {
private:
    struct FunctionInfo {
        std::string Name;
        std::string ModuleName;

        FunctionInfo(const std::string& name, const std::string& moduleName)
            : Name(name), ModuleName(moduleName) {}
    };

    static std::vector<FunctionInfo> functions;
    static BYTE originalBytes[17][6];
    static HANDLE processHandle;
    static DWORD targetProcessId;

    static void Initialize() {
        processHandle = nullptr;
        targetProcessId = 0;
    }

    static DWORD GetTargetProcessId() {
        DWORD processId = 0;
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            
        std::cout << "waiting for cs2.exe process..." << std::endl;
        while (true) {
            if (Process32First(snapshot, &entry)) {
                do {
                    if (strcmp(entry.szExeFile, "cs2.exe") == 0) {
                        processId = entry.th32ProcessID;
                        CloseHandle(snapshot);
                        return processId;
                    }
                } while (Process32Next(snapshot, &entry));
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
    }

    static void BypassHooks() {
        for (const auto& function : functions) {
            if (!Unhook(function.Name.c_str(), function.ModuleName.c_str())) {
                throw std::runtime_error("failed to unhook function.");
            }
        }
    }

    static void RestoreHooks() {
        for (const auto& function : functions) {
            if (!RestoreHook(function.Name.c_str(), function.ModuleName.c_str())) {
                throw std::runtime_error("failed to restore hook.");
            }
        }
    }

    static bool Unhook(const char* functionName, const char* moduleName) {
        HMODULE moduleHandle = GetModuleHandle(moduleName);
        if (moduleHandle == nullptr) {
            throw std::runtime_error("failed to get module handle.");
        }

        FARPROC functionAddress = GetProcAddress(moduleHandle, functionName);
        if (functionAddress == nullptr) {
            throw std::runtime_error("failed to get function address.");
        }

        BYTE originalBytes[6];
        ReadProcessMemory(processHandle, functionAddress, originalBytes, sizeof(originalBytes), nullptr);

        for (int i = 0; i < sizeof(originalBytes); i++) {
            Injector::originalBytes[i][i] = originalBytes[i];
        }

        return WriteProcessMemory(processHandle, functionAddress, Injector::originalBytes, sizeof(originalBytes), nullptr);
    }

    static bool RestoreHook(const char* functionName, const char* moduleName) {
        HMODULE moduleHandle = GetModuleHandle(moduleName);
        if (moduleHandle == nullptr) {
            throw std::runtime_error("failed to get module handle.");
        }

        FARPROC functionAddress = GetProcAddress(moduleHandle, functionName);
        if (functionAddress == nullptr) {
            return false;
        }

        return WriteProcessMemory(processHandle, functionAddress, Injector::originalBytes, sizeof(Injector::originalBytes), nullptr);
    }

    static void InjectDLL(const std::string& dllPath) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
        if (handle == nullptr) {
            throw std::runtime_error("failed to open process.");
        }

        SIZE_T size = dllPath.length() + 1;
        LPVOID dllMemory = VirtualAllocEx(handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (dllMemory == nullptr) {
            throw std::runtime_error("memory allocation error.");
        }

        if (!WriteProcessMemory(handle, dllMemory, dllPath.c_str(), size, nullptr)) {
            throw std::runtime_error("memory write error.");
        }

        HMODULE kernel32Handle = GetModuleHandle("Kernel32.dll");
        FARPROC loadLibraryAAddress = GetProcAddress(kernel32Handle, "LoadLibraryA");
        if (loadLibraryAAddress == nullptr) {
            throw std::runtime_error("failed to get LoadLibraryA address.");
        }

        HANDLE threadHandle = CreateRemoteThread(handle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAAddress, dllMemory, 0, nullptr);
        if (threadHandle == nullptr) {
            throw std::runtime_error("failed to create remote thread.");
        }

        WaitForSingleObject(threadHandle, INFINITE);
        CloseHandle(threadHandle);
        CloseHandle(handle);
        VirtualFreeEx(handle, dllMemory, 0, MEM_RELEASE);
    }

public:
    static bool Inject(const std::string& dllPath) {
        Initialize();
        
        targetProcessId = GetTargetProcessId();
        if (targetProcessId == 0) {
            throw std::runtime_error("the target process was not found.");
        }
        std::cout << "process cs2.exe found.";
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
        if (processHandle == nullptr) {
            throw std::runtime_error("failed to open target process.");
        }

        BypassHooks();
        InjectDLL(dllPath);
        RestoreHooks();

        return true;
    }
};

BYTE Injector::originalBytes[17][6] = { 0 };
HANDLE Injector::processHandle = nullptr;
DWORD Injector::targetProcessId = 0;
std::vector<Injector::FunctionInfo> Injector::functions = {
    { "LoadLibraryExW", "kernel32" },
    { "VirtualAlloc", "kernel32" },
    { "FreeLibrary", "kernel32" },
    { "LoadLibraryExA", "kernel32" },
    { "LoadLibraryW", "kernel32" },
    { "LoadLibraryA", "kernel32" },
    { "VirtualAllocEx", "kernel32" },
    { "LdrLoadDll", "ntdll" },
    { "NtOpenFile", "ntdll" },
    { "VirtualProtect", "kernel32" },
    { "CreateProcessW", "kernel32" },
    { "CreateProcessA", "kernel32" },
    { "VirtualProtectEx", "kernel32" },
    { "FreeLibrary", "KernelBase" },
    { "LoadLibraryExA", "KernelBase" },
    { "LoadLibraryExW", "KernelBase" },
    { "ResumeThread", "KernelBase" }
};
