TRS4R3NSpectreEye
A Windows Low-Level Memory Analysis Engine For Defensive Security Research - Bypass-Resillient Threat Detection via Direct syscall Architecture.

PROJECT CODE            LANGUAGE            PLATFORM            DOMAIN
TRS4R3N-SpectreEye      C++ / MASM x64      Windows 10/11 x64   Threat Detection / DFIR

1.ABSTRACT
Project Overview & Research Significance;
SpectreEye is a prototype low-level memory analysis engine designed for defensive security research on the Windows x64 platform. The project investigates the viability of constructing a bypass-resilient threat detection framework that operates independently of user-mode API layers, which are routinely intercepted and manipulated by both malicious actors and commercial Endpoint Detection & Response (EDR) solutions.

The core innovation of SpectreEye lies in its implementation of the Halo's Gate dynamic syscall resolution algorithm, combined with a hand-crafted MASM (Microsoft Macro Assembler) direct syscall invocation layer. This architecture enables the engine to enumerate system processes and perform deep virtual memory inspection entirely below the reach of conventional user-mode hook-based monitoring, representing a meaningful research contribution to the field of OS-level security forensics.

The engine detects two primary classes of memory-resident threat indicators: classic Process Injection and Process Hollowing artifacts (hidden Portable Executable images), and advanced EDR-evasion patterns characterized by anomalous private RWX memory regions with cleared PE signatures — a technique commonly employed by sophisticated adversaries.

2.ARCHITECTURE & DIAGRAM
System Architecture Diagram;
SpectreEye is structured into three distinct layers: a high-level C++ orchestration layer, a Halo's Gate resolver, and a low-level MASM direct syscall invocation layer. This separation ensures clean isolation between policy logic and kernel communication.
<img width="886" height="601" alt="d1" src="https://github.com/user-attachments/assets/f9f55b76-7cb7-4b5e-a726-ebbf1d8ddefe" />

Halo's Gate Algorithm — Syscall Resolution Flow
<img width="884" height="355" alt="d2" src="https://github.com/user-attachments/assets/8690b3e1-092a-4a2e-934b-d44c51274457" />

Virtual Memory Scan Loop — Threat Detection Logic
<img width="885" height="414" alt="d3" src="https://github.com/user-attachments/assets/b763836f-c3b5-48d6-ac11-97ccb4a58703" />

3.Core Features
Technical Capabilities;
Halo's Gate Syscall Resolver:  Dynamically resolves Windows NT syscall numbers at runtime. When EDR hooks overwrite a function with an E9 JMP instruction, the algorithm walks neighboring stubs (±32-byte alignment boundaries) to reconstruct the correct syscall index.
MASM Direct Syscall Invocation:  Hand-crafted x64 MASM assembly stubs invoke Windows NT kernel services directly via the syscall instruction, bypassing the entire ntdll.dll user-mode call path that EDR solutions monitor.
Process Injection Detection:  Scans all committed private memory regions of every running process. Identifies hidden PE (Portable Executable) payloads by checking for MZ magic bytes in executable memory — the hallmark of process injection and hollowing attacks.
Heuristic Anomaly Detection:  Advanced second-stage heuristic that detects cleared-MZ, private RWX regions — a technique used by sophisticated adversaries to evade signature-based detection while maintaining executable shellcode in memory.
System-Wide Process Sweep:  Enumerates all running processes without using high-level Win32 APIs (no CreateToolhelp32Snapshot). Uses NtQuerySystemInformation(SystemProcessInformation) to traverse raw process topology structures directly.
Structured Exception Handling:  All low-level byte inspection and memory access operations are wrapped in SEH __try/__except blocks, ensuring the scanner remains resilient against access violations when inspecting protected kernel or hypervisor-guarded process spaces.

4.THREAT INTELLIGENCE
Detected Indicators of Compromise (IoC)
SpectreEye implements two complementary detection strategies that together address both traditional and advanced evasion-aware injection techniques.

INDICATOR A — CRITICAL: Hidden PE Executable / Process Injection Payload Memory region is MEM_PRIVATE · MEM_COMMIT with PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ protection, and the first two bytes read as 4D 5A (MZ). This is the canonical signature of process injection (shellcode loaders, reflective DLL injection) and process hollowing, where a legitimate process image is replaced with a malicious PE in memory.

INDICATOR B — HEURISTIC: Deleted MZ Header in Private RWX Region Memory region is PAGE_EXECUTE_READWRITE private, but the MZ signature has been deliberately overwritten. This advanced evasion technique is used by sophisticated malware (e.g., post-Cobalt Strike loaders) to defeat signature-scanning tools that rely on MZ detection, while the payload itself remains executable. SpectreEye's heuristic engine flags these as potential dynamic code generation or EDR evasion risks.

Attack Techniques Covered;
Technique(MITRE ATT&CK)                               Detection Method                                   Indicator
T1055        Process Injection                        MZ header scan in private executable memory	       Indicator A (Critical)
T1055.012    Process Hollowing	                      Unmapped private RWX region with PE signature	     Indicator A (Critical)
T1027        Obfuscated Files / Reflective DLL	      Private RWX with cleared/absent MZ	               Indicator B (Heuristic)
T1562.001    Disable Security Tools (EDR Evasion)	    Halo's Gate detects and circumvents hooked stubs	 Engine-Level (Prevention)
T1620        Reflective Code Loading	                RWX private region without backing image	         Indicator B (Heuristic)

5.Technical Specifications
Implementation Details;

COMPONENT                    SPESIFICATION
Language	                   C++17 (MSVC) + MASM x64 (Microsoft Macro Assembler) — mixed-mode compilation with extern "C" linkage
Syscall Interface	           5 native NT APIs: NtOpenProcess, NtReadVirtualMemory, NtQueryVirtualMemory, NtQuerySystemInformation, NtQueryInformationThread
Hook Detection	             Halo's Gate algorithm — byte pattern matching (0x4C 0x8B 0xD1 0xB8), E9 JMP detection, ±32-byte neighbor walk with ±idx correction formula
Memory Enumeration	         SystemProcessInformation (class 5) via NtQuerySystemInformation — raw SYSTEM_PROCESS_INFORMATION structure traversal, 1MB dynamic buffer
Scan Granularity	           Per-page VirtualQuery walk via NtQueryVirtualMemory (MemoryBasicInformation) — complete address space coverage from 0x0 to upper boundary
Exception Safety	           SEH __try/__except (EXCEPTION_EXECUTE_HANDLER) at both resolver and scanner levels — full resilience against STATUS_ACCESS_VIOLATION
Platform	                   Windows 10 / 11 x64 (NT 10.0+) — requires elevated privileges for cross-process memory access
Console Output	             ANSI VT100 sequences via ENABLE_VIRTUAL_TERMINAL_PROCESSING — color-coded severity levels (red / yellow / green / cyan)
Error Handling	             C++ exception hierarchy (std::runtime_error) + catch(...) for unclassified faults, all with informational NTSTATUS codes

"// Halo's Gate — Core Resolution Logic WORD GetSyscallNumber(LPCSTR functionName) { PBYTE pFunc = (PBYTE)GetProcAddress(hNtdll, functionName); // Scenario A: Clean stub — syscall number at offset +4 if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) return *(PWORD)(pFunc + 4); // Scenario B: E9 JMP hook — walk ±32-byte aligned neighbors if (pFunc[0] == 0xE9) { for (WORD idx = 1; idx <= 500; idx++) { PBYTE pDown = pFunc + (idx * 32); // syscall# − idx PBYTE pUp = pFunc - (idx * 32); // syscall# + idx if (IsCleanStub(pDown)) return *(PWORD)(pDown + 4) - idx; if (IsCleanStub(pUp)) return *(PWORD)(pUp + 4) + idx; } } }"

6.Research Significance
Academic & Applied Research Value;
SpectreEye addresses a fundamental gap in contemporary endpoint security research: the inability of user-mode monitoring frameworks to operate reliably in environments where their own telemetry hooks may be bypassed by adversaries.

Academic Contributions;
-  Novel application of Halo's Gate algorithm in a defensive scanner context
-  Empirical study of EDR hook detection and bypass at the binary instruction level
-  Documented taxonomy of memory-resident IoC patterns and their PE-structure signatures
-  Prototype for kernel-adjacent monitoring without a kernel-mode driver (KMD)
-  Formal analysis of Windows NT native API call dispatch mechanisms

Industry Applications
-  Foundation for a next-generation HIDS (Host Intrusion Detection System) component
-  Integration candidate for DFIR (Digital Forensics & Incident Response) toolkits
-  Reference implementation for EDR-resilient telemetry engines
-  Red team simulation baseline for validating blue team detection coverage
-  Security Operations Center (SOC) supplementary memory audit tool

 Research Directions
-  Extension to kernel-mode driver (KMD) architecture for ring-0 telemetry
-  ETW (Event Tracing for Windows) integration for correlated threat analysis
-  Machine learning-assisted heuristic classification of anomalous memory patterns
-  Thread-level analysis via NtQueryInformationThread for stack walking
-  Cross-process handle inheritance and token impersonation detection

Geopolitical Relevance
-  Aligns with national cybersecurity strategy objectives for critical infrastructure protection
-  Addresses APT (Advanced Persistent Threat) detection capabilities gap
-  Supports development of domestically-engineered security tooling
-  Foundation for academic collaboration in OS-level security research
-  Contributes to the international body of open defensive security knowledge

7.Development Roadmap
Phase 1 Prototype:Current State,Halo's Gate +,Basic IoC Scan
Phase 2 Thread Analysis: Stack walk, TEB,inspection via,NtQueryInfoThread
Phase 3 ETW Integration: Event correlation,real-time provider consumption
Phase 4 ML Heuristics: Anomaly classifier trained on memory telemetry datasets
Phase 5 KMD / Full HIDS: Kernel-mode driver,ring-0 telemetry pipeline

License:Apache 2.0
Author: Serhan Kırca
LinkedIN:serhankirca
YouTube:@SerhanKırca
Medium:serhankirca
