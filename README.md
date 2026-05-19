Windows Low-Level Memory Analysis Prototype (C++ / MASM) = Spectre Eye

Overview
This project is a low-level Windows memory analysis prototype designed for educational and research purposes.

It explores Windows Internals using C++ and MASM by leveraging native system calls to analyze process memory behavior and virtual memory structures.

The goal is to understand how modern Windows systems manage processes, memory regions, and execution contexts from a defensive research perspective.

Features
- Enumeration of system processes using native system interfaces
- Scanning of virtual memory regions within target processes
- Detection of executable and private memory allocations
- Identification of suspicious PE (MZ header) signatures in memory
- Heuristic detection of anomalous executable memory regions (e.g., RWX allocations)

Architecture
The project is built in a layered structure:

C++ Application Layer  
↓  
MASM-Based System Call Interface  
↓  
Windows Native System Services  

This separation allows low-level interaction with Windows internals while maintaining a structured application design.
<img width="1042" height="540" alt="2" src="https://github.com/user-attachments/assets/4416be17-03a4-4a2f-a976-b415e0c31399" />
TRS4R3N Spectre Eye Startup Screen(Console)

<img width="2466" height="791" alt="Screenshot 2026-05-19 114245" src="https://github.com/user-attachments/assets/97a31df0-1340-42d5-820b-7ad9a3eea7dc" />
TRS4R3N Spectre Eye Software Tested with shellcode

Key Concepts Used
- Windows Internals
- Virtual Memory Management
- Native API / System Calls
- Process Memory Analysis
- Defensive Security Research Techniques
- x64 Assembly Integration (MASM)

Purpose
The purpose of this project is purely educational.
It is intended to improve understanding of:
- How Windows handles process memory
- How system calls operate at a low level
- How memory regions can be analyzed for anomalies
- How modern defensive tools inspect runtime behavior

Disclaimer
This project is developed strictly for educational and research purposes.
It is not intended for malicious use, exploitation, or unauthorized system access.

Notes
This project was developed as part of a personal study on:
- Windows Internals
- Low-level system programming
- Memory analysis techniques
- Syscall-based execution models

Future Improvements
- Enhanced memory forensics capabilities
- Thread and stack analysis
- ETW-based telemetry integration
- PE structure deep parsing
- Improved heuristic detection models

---
Author : Serhan Kırca
Personal research project focused on low-level Windows system behavior and defensive security concepts.
