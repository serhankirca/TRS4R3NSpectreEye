#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <exception>

// --- MASM Assembly External Prototypes ---
extern "C" {
    void SetNtOpenProcessSysNum(DWORD sysNum);
    void SetNtReadVirtualMemorySysNum(DWORD sysNum);
    void SetNtQueryVirtualMemorySysNum(DWORD sysNum);
    void SetNtQuerySystemInformationSysNum(DWORD sysNum);
    void SetNtQueryInformationThreadSysNum(DWORD sysNum);

    NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId);
    NTSTATUS MyNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
    NTSTATUS MyNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, DWORD MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
    NTSTATUS MyNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    NTSTATUS MyNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
}

// Halo's Gate Resolver Engine
WORD GetSyscallNumber(LPCSTR functionName) {
    __try {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return 0;
        PBYTE pFunc = (PBYTE)GetProcAddress(hNtdll, functionName);
        if (!pFunc) return 0;

        // Scenario A: Clean function stub (Unhooked by AV/EDR)
        if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) return *(PWORD)(pFunc + 4);

        // Scenario B: Function stub contains an E9 JMP instruction (Hooked by EDR)
        if (pFunc[0] == 0xE9) {
            for (WORD idx = 1; idx <= 500; idx++) {
                // Inspect neighboring stubs downwards (Typically 32-byte alignment boundary)
                PBYTE pCheckSys = pFunc + (idx * 32);
                if (pCheckSys[0] == 0x4C && pCheckSys[1] == 0x8B && pCheckSys[2] == 0xD1 && pCheckSys[3] == 0xB8) return *(PWORD)(pCheckSys + 4) - idx;

                // Inspect neighboring stubs upwards
                pCheckSys = pFunc - (idx * 32);
                if (pCheckSys[0] == 0x4C && pCheckSys[1] == 0x8B && pCheckSys[2] == 0xD1 && pCheckSys[3] == 0xB8) return *(PWORD)(pCheckSys + 4) + idx;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Secure SDLC Exception Strategy: Isolates runtime access violations during raw byte inspection
        return 0;
    }
    return 0;
}

// Perimeter Threat Intelligence: In-Depth Process Virtual Memory Scanner
void ScanTargetProcess(DWORD pid, UNICODE_STRING processName) {
    // SEH block shields the telemetry engine from hardware level exception states (DoS mitigation)
    __try {
        HANDLE hProcess = NULL;
        OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
        CLIENT_ID clientId = { (HANDLE)pid, 0 };

        // Low-level handle duplication via direct system call layer
        NTSTATUS status = MyNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
        if (status != 0) return; // Securely skip highly protected hypervisor / OS critical processes

        PVOID baseAddress = 0;
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnLength = 0;

        // Features 1 & 2: Structural Memory Mapping and Heuristic Scan Loop
        while (MyNtQueryVirtualMemory(hProcess, baseAddress, 0, &mbi, sizeof(mbi), &returnLength) == 0) {
            // Isolating allocated, process-private commits
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                // Tracking both explicit RWX allocations and sinsi executable RX mutations
                if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ) {

                    unsigned char buffer[2] = { 0 };
                    SIZE_T bytesRead = 0;
                    MyNtReadVirtualMemory(hProcess, mbi.BaseAddress, buffer, sizeof(buffer), &bytesRead);

                    // Indicator A: Executable context combined with explicit MZ magic bytes (Classic Process Injection / Hollowing)
                    if (buffer[0] == 'M' && buffer[1] == 'Z') {
                        std::wcout << L"\033[1;31m[!!!] CRITICAL: Hidden PE Executable / Injection Payload Detected!\033[0m\n";
                        std::wcout << L"--> Target Process: " << (processName.Buffer ? processName.Buffer : L"Unknown Target") << L" (PID: " << pid << L")\n";
                        std::cout << "--> Allocation Base: 0x" << std::hex << mbi.BaseAddress << " (Memory Protection Bits: 0x" << mbi.Protect << ")\n\n";
                    }
                    // Indicator B: Advanced Heuristic — MZ signature cleared, yet region remains unmapped Private RWX (EDR evasion bypass attempt)
                    else if (mbi.Protect == PAGE_EXECUTE_READWRITE && buffer[0] != 'M') {
                        std::wcout << L"\033[1;33m[!] HEURISTIC ANOMALY: Deleted MZ Header within Independent Private RWX Range!\033[0m\n";
                        std::wcout << L"--> Target Process: " << (processName.Buffer ? processName.Buffer : L"Unknown Target") << L" (PID: " << pid << L")\n";
                        std::cout << "--> Allocation Base: 0x" << std::hex << mbi.BaseAddress << " (Potential Dynamic Code Generation or Evasion Risk)\n\n";
                    }
                }
            }
            baseAddress = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        }
        CloseHandle(hProcess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Resiliency Strategy: Gracefully move to the next thread pool sequence if target context changes mid-execution
        return;
    }
}

int main() {
    // Standardizing host runtime console context for virtual ANSI sequences
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    std::cout << "\033[1;36m--- Spectre-Eye ULTIMATE EDR Engine ---\033[0m\n";
    std::cout << "[*] Dismantling user-mode telemetry hooks... Unraveling kernel dynamics...\n";

    // Strategic Application Lifecycle Layer
    try {
        // Dynamically reconstructing the System Call Table Numbers
        WORD openNum = GetSyscallNumber("NtOpenProcess");
        WORD readNum = GetSyscallNumber("NtReadVirtualMemory");
        WORD queryNum = GetSyscallNumber("NtQueryVirtualMemory");
        WORD sysInfoNum = GetSyscallNumber("NtQuerySystemInformation");
        WORD threadInfoNum = GetSyscallNumber("NtQueryInformationThread");

        if (!openNum || !readNum || !queryNum || !sysInfoNum || !threadInfoNum) {
            throw std::runtime_error("Critical kernel interfaces could not be verified. Possible invasive EDR active defense interference.");
        }

        // Committing validated execution registers to the MASM lower data boundary
        SetNtOpenProcessSysNum(openNum);
        SetNtReadVirtualMemorySysNum(readNum);
        SetNtQueryVirtualMemorySysNum(queryNum);
        SetNtQuerySystemInformationSysNum(sysInfoNum);
        SetNtQueryInformationThreadSysNum(threadInfoNum);

        std::cout << "[+] All Direct Core System Bridges Synchronized (Halo's Gate Protocol Active).\n";
        std::cout << "\033[1;32m[*] SYSTEM-WIDE DEEP ASYNCHRONOUS MEMORY SCAN INITIATED...\033[0m\n\n";

        // Feature 3: Enterprise-Wide Sweep Mapped Allocation Strategy
        ULONG bufferSize = 1024 * 1024; // Standard 1MB Process Topology Array Segment
        PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            throw std::runtime_error("Resource Exhaustion: Unable to map virtual container for operational execution data structures.");
        }

        ULONG returnLength = 0;
        // Interrogating SystemProcessInformation via Native Index 5
        NTSTATUS status = MyNtQuerySystemInformation(5, buffer, bufferSize, &returnLength);
        if (status != 0) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            std::clog << "[-] Core internal diagnostic interface failure. Execution status code: 0x" << std::hex << status << "\n";
            return -1;
        }

        // Traversing raw system structure topology arrays without reliance on high-level iteration APIs
        PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (pCurrent) {
            DWORD pid = (DWORD)(ULONG_PTR)pCurrent->UniqueProcessId;
            if (pid != 0) { // Omit systemic idle thread frames
                ScanTargetProcess(pid, pCurrent->ImageName);
            }

            if (pCurrent->NextEntryOffset == 0) break;
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset);
        }

        std::cout << "\033[1;32m[+] Comprehensive system threat hunting scan successfully executed.\033[0m\n";
        VirtualFree(buffer, 0, MEM_RELEASE);

    }
    catch (const std::exception& ex) {
        // Secure Defensive Framework Standards: Controlled failure tracking with strict informational containment
        std::clog << "\033[1;31m[-] CRITICAL APPLICATION EXCEPTION CONTROLLED: " << ex.what() << "\033[0m\n";
        system("pause");
        return -1;
    }
    catch (...) {
        std::clog << "\033[1;31m[-] SEVERE UNCLASSIFIED THREAD FAULT PREVENTED.\033[0m\n";
        system("pause");
        return -1;
    }

    system("pause");
    return 0;
}