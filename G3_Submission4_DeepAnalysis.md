# Digital Forensics Investigation Report: Deep Analysis Findings (Submission 4)
**Course:** Cyber Crime and Digital Forensic  
**Project:** Digital Forensics Investigation Project: Evidence-Based Cyber Crime Analysis (Memory Forensics)  
**Deliverable File:** `G3_Submission4_DeepAnalysis.md`

---

## 1. Group Information

* **Group Identifier:** Group 3 — Memory Forensics / RAM Image Analysis
* **Project Title:** Digital Forensics Investigation Project: Evidence-Based Cyber Crime Analysis (Memory Forensics)
* **Team Members & Responsibilities:**
  * **นายกวิน ฟุคุนิชิ (Student ID: 66128220101)** — *Lead Investigator & Tool Operator*  
    *Responsibilities:* Executes Volatility 3 and Volatility 2 plugins, leads forensic tool configuration, runs extraction and carving scripts, and oversees memory anomaly analysis.
  * **นายกิตติพงษ์ ตรุณพิณ (Student ID: 66128220102)** — *Evidence Recorder*  
    *Responsibilities:* Logs command execution, records tool outputs, verifies raw command logs, and structures forensic timelines.
  * **นายธีรพร เหล่าระเหว (Student ID: 66128220108)** — *Evidence Recorder*  
    *Responsibilities:* Calculates cryptographic hashes, manages chain of custody, and cross-verifies artefact integrity.
  * **นายโภคิณ ตุมิภาค (Student ID: 66128220112)** — *Report Lead*  
    *Responsibilities:* Synthesizes forensic findings, compiles the technical report, formats structural breakdowns, and prepares analytical visualizations.

---

## 2. Evidence Reference

| Evidence Parameter | Details / Specification |
|---|---|
| **Evidence Identifier** | `G3-EV-001` *(authoritative per Submissions 2, 3, and 4)* |
| **Case Scenario** | "My system was recently compromised. The hacker stole a lot of information but also deleted a very important file. Only evidence available is this memory dump." |
| **Dataset Origin** | MemLabs Lab 4 – Obsession (stuxnet999 repository) |
| **Original Archive File** | `ML4.7z` (original: `MemLabs-Lab4.7z`) |
| **Original Evidence Path** | `/home/engineer/Documents/University/MemoryForensic/Original_Files/MemoryDump_Lab4.raw` |
| **Working Copy File** | `MemoryDump_Lab4_Copy.raw` |
| **Working Copy Path** | `/home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw` |
| **Evidence Received** | 14 กรกฎาคม 2569, ~11:00 AM ICT, on Kali Linux VM |
| **Cryptographic Hash (MD5)** | `d2bc2f671bcc9281de5f73993de04df3` *(Verified matching across Original and Working Copy)* |
| **Cryptographic Hash (SHA-256)** | `3c6dc1567ad62bb4a0ed21b98ed2e20673fef12f5109fce131d89fd74e29235` *(Computed 10 ส.ค. 2569 16:05/16:06 ICT, 100% bitwise match)* |

> **Forensic Integrity Statement:**  
> In strict compliance with digital forensics principles and ISO/IEC 27037 standards, **all analysis actions, Volatility plugins, and memory carving procedures were performed exclusively on the Working Copy (`MemoryDump_Lab4_Copy.raw`)**. The Original Evidence file remains write-protected, unmoved, and completely unaltered in the `Original_Files/` storage directory.

---

## 3. Analysis Scope

Following the completion of the Initial Triage Report (Submission 3), which scoped out potential processes of interest and mapped out preliminary file offsets, Submission 4 transitions the investigation from basic triage to in-depth forensic verification and evidentiary recovery.

The deep-analysis scope encompasses:
1. **OS Kernel & Subsystem Baseline:** Extracting exact operating system build, service pack levels, kernel base address, and memory architecture via `windows.info`.
2. **Process Hierarchy & Termination Reconstruction:** Executing comparative analysis between active process lists (`windows.pslist`) and unallocated memory pool structures (`windows.psscan`) to identify unlinked or terminated processes.
3. **Command Line & Environment Enumeration:** Extracting process arguments (`windows.cmdline`) and environment variables (`windows.envars`) to correlate user accounts, system paths, and host metadata.
4. **Code Injection & Volatile Memory Scanning:** Performing VAD-level inspection via `windows.malfind` across all processes to evaluate anomalous `PAGE_EXECUTE_READWRITE` memory allocations.
5. **Per-PID Deep Inspection:** Conducting targeted module (`windows.dlllist`) and resource handle (`windows.handles`) audits on priority processes:
   * PID 2624 (`DumpIt.exe` — user `eminem`, Session 1)
   * PID 2432 (`StikyNot.exe` — user `SlimShady`, Session 2)
   * PID 1944 & PID 3012 (`explorer.exe` — sessions 1 and 2)
   * PID 1688 (`SearchFilterHost.exe`) & PID 2076 (`dllhost.exe`)
6. **Network Profile Verification:** Auditing network sockets, connection tables, and listening ports via `windows.netscan`.
7. **Artefact Extraction & Carving:** Extracting cached file streams from memory via physical address offsets (`windows.dumpfiles --physaddr`), computing cryptographic integrity hashes (MD5, SHA-256), and inspecting file internals (`file`, `strings`, `steghide`).
8. **Steganographic Analysis & Decoy Extraction:** Extracting hidden streams embedded within image artefacts (`galf.jpeg`) using empty passphrase authentication without brute-forcing.
9. **Volatile Clipboard Subsystem Auditing:** Assessing clipboard contents across user sessions via Volatility clipboard frameworks to test investigator hints discovered in user notes.
10. **Physical Memory Resident File Carving:** Performing targeted memory carving to locate in-memory Master File Table (MFT) records and reconstruct resident data attributes (`$DATA`) of deleted files (`Important.txt`).
11. **User Activity & Execution Tracking:** Inspecting NTUSER.DAT registry hives, ShellBags, and UserAssist keys (`windows.registry.userassist`) to reconstruct user actions across both profiles.

---

## 4. Updated Method Log

The method log records every operational step, tool invocation, diagnostic check, error encountered, and correction made during the deep analysis session.

| # | Date/Time (ICT) | Analyst/Agent | Tool | Command | Reason | Result | Output file |
|---|---|---|---|---|---|---|---|
| 1 | 23 Aug 2026, 13:18 | นายกวิน ฟุคุนิชิ / Agent | uv / Bash | `cd /home/engineer/Documents/University/MemoryForensic/volatility3-2.28.0 && uv sync` | Environment initialization and venv package synchronization (fix ModuleNotFoundError) | Virtual environment successfully rebuilt; `vol` command functional | N/A (terminal log) |
| 2 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.info` | Baseline re-confirmation: retrieve exact OS build, architecture, and memory snapshot timestamp (F-001) | Identified Windows 7 SP1 (6.1 build 7601.17514 amd64), 1 CPU, capture time 2019-06-29 07:30:00 UTC | `raw_output/01_windows.info.txt` |
| 3 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.pslist` | Process list extraction: enumerate active processes linked in ActiveProcessLinks | Retrieved 35 active processes across Session 0, 1 (eminem), and 2 (SlimShady) | `raw_output/02_windows.pslist.txt` |
| 4 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.psscan` | Process pool scanning: detect hidden, unlinked, or terminated processes via pool tag scanning | Found 38 process objects; identified 3 terminated processes (csrss.exe PID 2672, LogonUI.exe PID 2148, dllhost.exe PID 2572) not present in pslist | `raw_output/03_windows.psscan.txt` |
| 5 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.cmdline` | Command-line parameter inspection: extract exact launch arguments for all processes (F-002, F-007) | Confirmed `DumpIt.exe` path `C:\Users\eminem\Desktop\DumpIt\DumpIt.exe`, StikyNot.exe, and VBox/system binaries | `raw_output/04_windows.cmdline.txt` |
| 6 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.envars` | Environment variables extraction: determine user contexts, system paths, and host metadata per PID | Confirmed COMPUTERNAME=2PAC, USERNAME=eminem (PID 1944) and USERNAME=SlimShady (PID 3012, 2432) | `raw_output/05_windows.envars.txt` |
| 7 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.malfind` | Code injection / suspicious memory scan: identify PAGE_EXECUTE_READWRITE (RWX) VADs with executable code | Flagged 5 PIDs: explorer.exe (1944, 3012), dllhost.exe (2076), SearchFilterHost (1688), StikyNot.exe (2432) | `raw_output/06_windows.malfind.txt` |
| 8 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.netscan` | Network artifacts verification: inspect network sockets, endpoints, and listening ports | Confirmed no external C2 or remote IP; only 0.0.0.0 listening ports, loopback 127.0.0.1, and local 10.0.2.15 (VBox NAT) | `raw_output/07_windows.netscan.txt` |
| 9 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.dlllist --pid 2624` | Per-PID deep dive: inspect loaded DLLs for DumpIt.exe (PID 2624) to evaluate H-002 | Standard Win32/SysWOW64 DLLs loaded (ntdll.dll, kernel32.dll, user32.dll); no injection detected | `raw_output/08_windows.dlllist_pid2624.txt` |
| 10 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.handles --pid 2624` | Per-PID deep dive: inspect open handles for DumpIt.exe (PID 2624) to verify file acquisition target | Identified physical memory device handle `\Device\PhysicalMemory` and raw dump file target `2PAC-20190629-072925.raw` | `raw_output/09_windows.handles_pid2624.txt` |
| 11 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.dlllist --pid 2432` | Per-PID deep dive: inspect loaded DLLs for StikyNot.exe (PID 2432) to evaluate F-007 | Standard Windows Sticky Notes binary and UI DLLs loaded; no anomalous DLLs | `raw_output/10_windows.dlllist_pid2432.txt` |
| 12 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.handles --pid 2432` | Per-PID deep dive: inspect open handles for StikyNot.exe (PID 2432) | Found open handle to `\Users\SlimShady\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt` | `raw_output/11_windows.handles_pid2432.txt` |
| 13 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.dlllist --pid 1944` | Per-PID deep dive: inspect loaded DLLs for eminem explorer.exe (PID 1944) | Normal Explorer shell modules and VirtualBox Tray extensions loaded | `raw_output/12_windows.dlllist_pid1944.txt` |
| 14 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.handles --pid 1944` | Per-PID deep dive: inspect open handles for eminem explorer.exe (PID 1944) | Handles open to eminem user profile directories, Desktop, and shell registry keys | `raw_output/13_windows.handles_pid1944.txt` |
| 15 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.dlllist --pid 3012` | Per-PID deep dive: inspect loaded DLLs for SlimShady explorer.exe (PID 3012) | Normal Explorer shell modules loaded under second session | `raw_output/14_windows.dlllist_pid3012.txt` |
| 16 | 23 Aug 2026, 13:19 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.handles --pid 3012` | Per-PID deep dive: inspect open handles for SlimShady explorer.exe (PID 3012) | Handles open to SlimShady profile, Notepad.exe file association keys, and temp log files | `raw_output/15_windows.handles_pid3012.txt` |
| 17 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.registry.hivelist` | Registry analysis: locate virtual and physical base offsets of user and system hives (4.9) | Located NTUSER.DAT for eminem (`0xf8a001a1c010`) and SlimShady (`0xf8a0021aa410`), and SYSTEM/SAM hives | `raw_output/16_windows.registry.hivelist.txt` |
| 18 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.registry.userassist` | Registry analysis: inspect execution frequency and timestamps from UserAssist subkeys | Decoded UserAssist run history for SlimShady (Sticky Notes run at 2019-06-27 12:43:13 UTC, Paint, Calculator, etc.) | `raw_output/17_windows.registry.userassist.txt` |
| 19 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --virtaddr 0x3e8ad250` | Extraction attempt for galf.jpeg using `--virtaddr` offset from filescan | Result was empty; physical offset `0x3e8ad250` was mistakenly passed to the `--virtaddr` parameter instead of the 64-bit kernel virtual address (`0xfa80022ad0f0`) or using `--physaddr` | N/A (0 bytes output) |
| 20 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3e8ad250` | Extraction fix for galf.jpeg using `--physaddr` (4.6, F-004) | Successfully dumped DataSectionObject: `file.0x3e8ad250.0xfa80022ad0f0.DataSectionObject.galf.jpeg.dat` (229,376 bytes) | `extracted/file.0x3e8ad250.0xfa80022ad0f0.DataSectionObject.galf.jpeg.dat` |
| 21 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3e8d1c80` | Extraction of galf.lnk shortcut (4.6, F-004) | Successfully dumped: `file.0x3e8d1c80.0xfa80022bd7b0.DataSectionObject.galf.lnk.dat` (4,096 bytes) | `extracted/file.0x3e8d1c80.0xfa80022bd7b0.DataSectionObject.galf.lnk.dat` |
| 22 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3fc398d0` | Extraction attempt for Important.txt (4.6, F-005) | No resident DataSectionObject in active RAM cache stream; cached pages unmapped upon deletion | N/A (no cache file dumped) |
| 23 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3f939720` | Extraction of Important.lnk shortcut (4.6, F-005) | Successfully dumped: `file.0x3f939720.0xfa80013f7e40.DataSectionObject.Important.lnk.dat` (4,096 bytes) | `extracted/file.0x3f939720.0xfa80013f7e40.DataSectionObject.Important.lnk.dat` |
| 24 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3fd40910` | Extraction of StickyNotes.snt container (4.10, F-007) | Successfully dumped: `file.0x3fd40910.0xfa8000f40590.DataSectionObject.StickyNotes.snt.dat` (4,096 bytes) | `extracted/file.0x3fd40910.0xfa8000f40590.DataSectionObject.StickyNotes.snt.dat` |
| 25 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3ebe2a20` | Extraction attempt of output dump 2PAC-20190629-072925.raw (4.11, H-002) | FileObject present in memory during acquisition write stream; no static data section dumpable | N/A (no cache file dumped) |
| 26 | 23 Aug 2026, 13:22 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3e8a85b0` | Extraction of Flag not here.lnk shortcut (F-008) | Successfully dumped: `file.0x3e8a85b0.0xfa80022ab770.DataSectionObject.Flag not here.lnk.dat` (4,096 bytes) | `extracted/file.0x3e8a85b0.0xfa80022ab770.DataSectionObject.Flag not here.lnk.dat` |
| 27 | 23 Aug 2026, 13:22 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3e8e5ba0` | Extraction of Screenshot1.lnk shortcut (F-009) | Successfully dumped: `file.0x3e8e5ba0.0xfa80022e54b0.DataSectionObject.Screenshot1.lnk.dat` (4,096 bytes) | `extracted/file.0x3e8e5ba0.0xfa80022e54b0.DataSectionObject.Screenshot1.lnk.dat` |
| 28 | 23 Aug 2026, 13:22 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3e8d19e0` | Extraction of Screenshot1.png image (F-009) | Successfully dumped: `file.0x3e8d19e0.0xfa80022d1670.DataSectionObject.Screenshot1.png.dat` (57,344 bytes) | `extracted/file.0x3e8d19e0.0xfa80022d1670.DataSectionObject.Screenshot1.png.dat` |
| 29 | 23 Aug 2026, 13:23 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.dlllist --pid 1688` | Per-PID deep dive: inspect DLLs for SearchFilterHost (PID 1688) flagged by malfind | Normal search indexing host DLLs (tquery.dll, mssprxy.dll); no injection | `raw_output/18_windows.dlllist_pid1688.txt` |
| 30 | 23 Aug 2026, 13:23 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.handles --pid 1688` | Per-PID deep dive: inspect handles for SearchFilterHost (PID 1688) | Open handles to search pipe Global\UsGthrFltPipeMssGthrPipe and search databases | `raw_output/19_windows.handles_pid1688.txt` |
| 31 | 23 Aug 2026, 13:23 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.dlllist --pid 2076` | Per-PID deep dive: inspect DLLs for dllhost.exe (PID 2076) flagged by malfind | COM Surrogate hosting Windows Photo Viewer thumbnail handlers (photowrap.dll, gdiplus.dll) | `raw_output/20_windows.dlllist_pid2076.txt` |
| 32 | 23 Aug 2026, 13:23 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.handles --pid 2076` | Per-PID deep dive: inspect handles for dllhost.exe (PID 2076) | Handles to temp thumbnail files (`~PID8EC.tmp`, `~PID92B.tmp`, `~PIDAB5.tmp`, `~PIE007.tmp`) in eminem's Temp folder | `raw_output/21_windows.handles_pid2076.txt` |
| 33 | 23 Aug 2026, 13:21 | นายกิตติพงษ์ ตรุณพิณ / Agent | Linux CLI (file/strings) | `file extracted/* && strings extracted/*` | Content inspection of all extracted artefacts (4.8) | Identified file types, extracted metadata from .lnk shortcuts, extracted RTF note from StickyNotes.snt | `raw_output/strings_*.txt` |
| 34 | 23 Aug 2026, 13:21 | นายธีรพร เหล่าระเหว / Agent | Linux CLI (md5sum / sha256sum) | `md5sum extracted/* && sha256sum extracted/*` | Compute integrity hashes for all 7 extracted artefacts (4.7) | Hash table populated with MD5 and SHA-256 for all 7 dumped files | `hashes.md` |
| 35 | 23 Aug 2026, 13:23 | นายกวิน ฟุคุนิชิ / Agent | steghide | `steghide info extracted/file.0x3e8ad250...galf.jpeg.dat -p ""` | Steganographic inspection of galf.jpeg to test H-001 | Detected embedded file `LMAO.txt` (38 bytes, encrypted rijndael-128 cbc); confirmed empty passphrase opens container structure | Terminal / report log |
| 36 | 13 Sep 2026, 08:46 | นายกวิน ฟุคุนิชิ / Agent | steghide | `steghide extract -sf extracted/file.0x3e8ad250.0xfa80022ad0f0.DataSectionObject.galf.jpeg.dat -p "" -xf extracted/LMAO.txt` | Extract hidden payload from galf.jpeg using verified empty passphrase ("") | Successfully extracted `LMAO.txt` (38 bytes); contents revealed anti-forensic decoy note: "Move on bro, there is nothing here :)" | `extracted/LMAO.txt`, `raw_output/23_steghide_extract_galf.txt` |
| 37 | 13 Sep 2026, 08:46 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw windows.clipboard` | Follow up StickyNotes clue regarding clipboard plugin in Volatility 3 | Returned error: `invalid choice windows.clipboard` (Volatility 3 lacks native windows.clipboard plugin; command syntax preserved) | `raw_output/22_windows.clipboard.txt` |
| 38 | 13 Sep 2026, 08:49 | นายกวิน ฟุคุนิชิ / Agent | Volatility 2.6.1 | `python2 vol.py -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw --profile=Win7SP1x64 clipboard -v` | Execute legacy clipboard extraction via Volatility 2 to evaluate StickyNotes clue | Extracted clipboard objects for Session 1 (`0x1010b`) and Session 2 (`0x100ff`); data contains only locale `0x0409` (en-US), no flag; confirms StickyNotes note was accurate | `raw_output/22_windows.clipboard.txt` |
| 39 | 13 Sep 2026, 08:49 | นายกวิน ฟุคุนิชิ / Agent | Python / Hex Carving | `python3 carve_mft.py MemoryDump_Lab4_Copy.raw` | Targeted memory carving for resident MFT record of deleted Important.txt | Discovered resident MFT record at physical offset 1004055552 (`0x3bd8ac00`); carved intact 153-byte resident `$DATA` attribute containing flag `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}` | `extracted/Important.txt`, `raw_output/24_carve_important_txt.txt` |
| 40 | 13 Sep 2026, 08:50 | นายธีรพร เหล่าระเหว / Agent | Linux CLI (md5sum / sha256sum) | `md5sum extracted/LMAO.txt extracted/Important.txt && sha256sum ...` | Cryptographic integrity verification for newly extracted artefacts | LMAO.txt: MD5 `24b2f7c3998a603c51394dc0736d37cb`, SHA-256 `9a1ec67f...`; Important.txt: MD5 `3b07cd60cbfc3ea0f41adcaf9824e27c`, SHA-256 `352b436e...` | `hashes.md` |

---

## 5. Deep Findings Table

The table below integrates the initial findings (F-001 through F-007) with updated evidence, confidence ratings, and new deep-analysis findings (F-008 through F-012).

| Finding ID | Finding Description | Evidence Source | Timestamp | Tool / Method | Supporting Evidence | Forensic Interpretation | Confidence | Status |
|---|---|---|---|---|---|---|---|---|
| **F-001** | OS Kernel Profile & Exact Memory Capture Baseline | Kernel memory layer | 2019-06-29 07:30:00 UTC | `windows.info` | NTBuildLab: `7601.17514.amd64fre.win7sp1_rtm.`, 64-bit AMD64, 1 CPU, Kernel Base `0xf80002605000` | Pinpoints OS as Windows 7 SP1 64-bit. Memory snapshot represents state at exactly 07:30:00 UTC. | **High** | Confirmed |
| **F-002** | Physical RAM Acquisition via MoonSols DumpIt | Process tree, command lines, handle tables | 2019-06-29 07:29:25 UTC | `windows.pslist`, `windows.cmdline`, `windows.handles` | PID 2624 launched as `"C:\Users\eminem\Desktop\DumpIt\DumpIt.exe"`, Wow64: True, handle to `\Device\PhysicalMemory` and `2PAC-20190629-072925.raw` | DumpIt was actively capturing physical RAM to disk at the time of snapshot, proving self-acquisition. | **High** | Confirmed |
| **F-003** | Dual Interactive Logon Architecture (eminem & SlimShady) | Process tree, environment blocks, LogonUI scan | 2019-06-29 07:28:44 – 07:29:36 UTC | `windows.pslist`, `windows.psscan`, `windows.envars` | Session 1: `eminem` (`explorer.exe` PID 1944, started 07:28:44 UTC); Session 2: `SlimShady` (`explorer.exe` PID 3012, started 07:29:36 UTC) preceded by `winlogon` (PID 2728) | Two interactive desktop sessions ran concurrently; user switching occurred right before RAM capture. | **High** | Confirmed |
| **F-004** | Steghide Payload Extraction from `galf.jpeg` & Decoy Identification | File table, dumped data section, steghide extraction | 2019-06-25 17:46:53 UTC (file mtime) | `windows.filescan`, `windows.dumpfiles`, `steghide extract` | FileObject `0x3e8ad250` dumped (229,376 B); Steghide container extracted with empty passphrase `""`, yielding `LMAO.txt` (38 B): *"Move on bro, there is nothing here :)"* | While "galf" is "flag" backwards, the embedded payload is an anti-forensic red herring designed to divert investigation. | **High** | Confirmed (Decoy Extracted) |
| **F-005** | Deletion of Critical Artefact `Important.txt` from SlimShady Profile | File table, link shortcuts, IE index.dat | 2019-06-27 18:26:12 UTC (mtime) | `windows.filescan`, `windows.dumpfiles`, strings grep | `Important.lnk` records target `C:\Users\SlimShady\Desktop\Important.txt` (153 B). `dumpfiles` at `0x3fc398d0` returned 0 cached pages. | Directly supports case briefing ("deleted a very important file"). Data was unmapped from active RAM cache before dump. | **High** | Confirmed (Deleted) |
| **F-006** | Absence of Active Remote C2 or External Network Sockets | Network table | 2019-06-29 07:28 – 07:30 UTC | `windows.netscan` | Only TCP/UDP listening on `0.0.0.0`, loopback `127.0.0.1`, and host interface `10.0.2.15` (VirtualBox NAT). No foreign IPs. | No established remote exfiltration channels existed at exact moment of snapshot (does not rule out past connections). | **High** | Confirmed |
| **F-007** | Recovery of In-Memory Note in `StickyNotes.snt` & Clipboard Clue Verification | Process table, handle table, carved OLE stream, Volatility clipboard | 2019-06-27 12:43:13 UTC (UserAssist) | `windows.handles`, `windows.dumpfiles`, `clipboard` | PID 2432 (`StikyNot.exe`) held open handle to `StickyNotes.snt` (`0x3fd40910`). Extracted RTF string: *"The clipboard plugin works well but it doesn't give the flag :P"*. Clipboard audit confirmed only locale `0x0409`. | Creator clue verified: clipboard contains no secret data; Sticky Note explicitly warns that clipboard analysis is a diversion. | **High** | Confirmed |
| **F-008** | Multi-Layered Anti-Forensic Deception & Decoy Ecosystem | Carved shortcut files, image rendering, text decoys | 2019-06-27 18:12:15 UTC (ctime) | `windows.dumpfiles`, `file`, `strings`, PIL crop | `Flag not here.lnk` (0 B target length), `Screenshot1.png` (*"This is a good lie and all but it won't help you :P"*), and `LMAO.txt` (*"Move on bro..."*). | Proves a deliberate, coordinated triad of decoy artefacts designed to exhaust triage resources. | **High** | Confirmed |
| **F-009** | Transient Process Pool Unlinking & Interactive Logon Sequence | Unallocated pool tags, process termination timestamps | 2019-06-29 07:29:51 – 07:30:07 UTC | `windows.psscan` vs `windows.pslist` | `psscan` revealed 3 terminated processes missing from `pslist`: `csrss.exe` (PID 2672), `LogonUI.exe` (PID 2148, exited 07:29:59 UTC), and `dllhost.exe` (PID 2572). | Accurately reconstructs the graphical logon transition into SlimShady's user session 1 second before RAM capture. | **High** | Confirmed |
| **F-010** | Forensic Invalidation of Malfind False Positives | Process VAD trees, DLL inspection, handle tables | 2019-06-29 07:29:02 – 07:30:00 UTC | `windows.malfind`, `windows.dlllist`, `windows.handles` | Malfind flagged RWX allocations in `explorer.exe`, `dllhost.exe`, `SearchFilterHost.exe`. DLL and handle inspection confirmed COM/GDI+ thumbnail rendering. | VAD anomalies are legitimate Windows subsystem rendering buffers (e.g. `gdiplus.dll`, `photowrap.dll`), not code injection. | **High** | Confirmed |
| **F-011** | Physical Memory MFT Carving & Full Recovery of Competition Flag | Raw physical RAM paging space, resident NTFS MFT record | 2019-06-27 18:26:12 UTC (mtime) | Direct hex carving, resident MFT parsing | Discovered resident MFT record at physical offset `1004055552` (`0x3bd8ac00`); extracted intact 153-byte `$DATA` attribute containing flag `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}` | Crucial case resolution: although the file cache was purged, NTFS resident file storage retained the full 153 bytes in memory, fully solving the case. | **High** | Confirmed (Flag Recovered) |
| **F-012** | Volatility Clipboard Plugin Architectural Divergence | Volatility 3 framework, Volatility 2 framework | 2026-09-13 (Analyst time) | `vol` (v3) vs `vol.py` (v2) | Volatility 3 v2.28.0 lacks `windows.clipboard` (`invalid choice`). Volatility 2.6.1 successfully resolved Session 1 (`0x1010b`) and Session 2 (`0x100ff`) handles. | Demonstrates technical framework evolution between Volatility 2 and Volatility 3; proves absence of flag in clipboard buffers. | **High** | Confirmed |

---

## 6. Evidence Support for Each Finding

Below is the deep-dive analysis for the most critical findings governing the case narrative.

### 6.1 Finding F-004: Artefact `galf.jpeg`, Steghide Extraction, and Decoy Verification
1. **What was found:**  
   A file named `galf.jpeg` located at `\Users\eminem\Desktop\galf.jpeg` and its corresponding shortcut `galf.lnk`. Steganographic analysis demonstrated that the JPEG encapsulated an embedded Steghide file named `LMAO.txt`. Extraction using an empty passphrase (`""`) yielded 38 bytes of plaintext: `"Move on bro, there is nothing here :)"`.
2. **Evidence source:**  
   * Memory dump physical offset `0x3e8ad250` (FileObject `0xfa80022ad0f0`)
   * Memory dump physical offset `0x3e8d1c80` (Shortcut `galf.lnk`)
   * Extracted payload: `deep_analysis/extracted/LMAO.txt`
3. **Discovery method:**  
   Identified via `windows.filescan`, extracted to disk using `windows.dumpfiles --physaddr 0x3e8ad250`, inspected via `steghide info`, and carved using `steghide extract -sf ... -p "" -xf deep_analysis/extracted/LMAO.txt`.
4. **Supporting evidence:**  
   * Dumped JPEG size: 229,376 bytes with valid JFIF header (`FF D8 FF E0`) and EOI at `0x37d18` (228,634 bytes).
   * Visual content: High-resolution illustration of the Joker character.
   * Embedded container: `steghide info` reported embedded file `LMAO.txt` (size: 38.0 bytes, encrypted: `rijndael-128, cbc`, compressed: yes).
   * Extracted file hash: MD5 `24b2f7c3998a603c51394dc0736d37cb`, SHA-256 `9a1ec67f5e3f22bc6c445709568d42ad0aa2df4af96898d71a1c7c3cff9dee70`.
   * Content:
     ```text
     Move on bro, there is nothing here :)
     ```
5. **Interpretation:**  
   While "galf" is the reverse spelling of "flag", this artefact was constructed as an elaborate anti-forensic red herring. The encryption utilized an empty passphrase (`""`), deliberately meant to tempt analysts into spending significant time attempting password recovery, only to reveal an explicit decoy message.
6. **Limitations:**  
   Steghide data hiding alters DCT coefficients; without knowing whether additional hidden channels exist, analysis is confined to the Steghide extraction output.
7. **Confidence & Reasoning:**  
   **High.** The empty passphrase successfully completed cryptographic decryption of the Steghide container, directly exposing the plain text decoy message.

---

### 6.2 Finding F-005 & F-011: Physical Memory MFT Carving & Complete Recovery of `Important.txt` (Flag)
1. **What was found:**  
   The deleted document `Important.txt` (`C:\Users\SlimShady\Desktop\Important.txt`), cited in the case scenario as the primary stolen/deleted asset, was successfully recovered in full (153 bytes) from an in-memory resident Master File Table (MFT) record. The file content reveals the authentic competition flag: `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`.
2. **Evidence source:**  
   * Physical memory offset `1004055552` (`0x3bd8ac00`): In-memory NTFS MFT Record (Record #0x39147)
   * Shell link metadata: `Important.lnk` at physical offset `0x3f939720`
   * Internet Explorer / Explorer history cache at memory offset `0x23b5c09e`
3. **Discovery method:**  
   Targeted memory scanning for `Important.txt` references in unallocated RAM paging space, discovery of the 1024-byte MFT record signature (`FILE0`), parsing of the resident `$DATA` attribute (type `0x80`), and byte-level extraction of the 153-byte payload.
4. **Supporting evidence:**  
   * **MFT Record Structure:**  
     * Magic identifier: `FILE0` at physical offset `1004055552` (`0x3bd8ac00`).
     * Standard Information (`0x10`): Creation `2019-06-27 18:14:13 UTC`, Modification `2019-06-27 18:26:12 UTC`.
     * File Name (`0x30`): `Important.txt` (DOS namespace: `IMPORT~1.TXT`), parent directory reference pointing to SlimShady's Desktop.
     * Data Attribute (`0x80`): Resident attribute header (`Form Code: 0x00`), attribute length `0xb8`, content size `0x99` (exactly **153 bytes**).
   * **Recovered Content (Exact 153 bytes):**
     ```text
     i


     n


     ct



     f{1


     _is


     _n0t



     _EQu4l



     _7o_2_bUt






     _th1s_d0s3nt



     _m4ke


     _s3n



     s3}

     Good work :P
     ```
   * **Reconstructed Flag:**  
     Concatenating the segmented token strings yields:  
     `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`
   * **Cryptographic Hashes of Carved File:**  
     * MD5: `3b07cd60cbfc3ea0f41adcaf9824e27c`  
     * SHA-256: `352b436ea0ee449631985c10e1610f124fa99e46583b1c7e8b0f7122b7b42708`
5. **Interpretation:**  
   In NTFS architecture, files smaller than approximately 700 bytes are stored as **resident data** directly within the MFT record itself rather than allocated to separate data clusters. When `Important.txt` was deleted, its active memory cache stream was detached (explaining why `windows.dumpfiles` returned 0 bytes), but the corresponding MFT record remained cached in physical memory paging pool, leaving the entire 153-byte content completely intact and recoverable.
6. **Limitations:**  
   Because the file was deleted, filesystem pointers in active tables were marked unallocated. Recovery relies on physical memory carve consistency, which in this case was 100% bitwise intact.
7. **Confidence & Reasoning:**  
   **High.** The carved MFT record conforms rigorously to NTFS filesystem specifications, the file size matches the 153 bytes recorded in `Important.lnk`, and the flag format matches the required `inctf{...}` specification.

---

### 6.3 Finding F-007 & F-012: In-Memory Sticky Notes Clue and Clipboard Subsystem Verification
1. **What was found:**  
   `StickyNotes.snt` held by `StikyNot.exe` (PID 2432) revealed the note: *"The clipboard plugin works well but it doesn't give the flag :P"*. Forensic verification across Volatility frameworks proved that the clipboard buffers contained no flag or credential, confirming the note's accuracy.
2. **Evidence source:**  
   * `StickyNotes.snt` at physical offset `0x3fd40910` (PID 2432 handle `0x21c`)
   * Volatility 2 `clipboard` output (`Session 1` handle `0x1010b`, `Session 2` handle `0x100ff`)
3. **Discovery method:**  
   Extracted `StickyNotes.snt` via `windows.dumpfiles --physaddr 0x3fd40910`, decoded RTF stream with `strings`, tested `vol windows.clipboard` in Volatility 3, and executed `python2 vol.py --profile=Win7SP1x64 clipboard -v` in Volatility 2.
4. **Supporting evidence:**  
   * Extracted text string from `StickyNotes.snt`:
     ```text
     {\rtf1\ansi\ansicpg1252\deff0\deflang1033{\fonttbl{\f0\fnil\fcharset0 Segoe Print;}}
     \viewkind4\uc1\pard\f0\fs20 The clipboard plugin works well but it doesn't give the flag :P\par
     }
     ```
   * Volatility 3 invocation returned: `invalid choice windows.clipboard` because Volatility 3 does not implement a native clipboard plugin.
   * Volatility 2 `clipboard -v` output revealed:
     * Session 1 (`0x1010b`): `0xfffff900c1eb75d4: 09 04 00 00` (Format `CF_LOCALE`: `0x0409` - English US)
     * Session 2 (`0x100ff`): `0xfffff900c1acd3a4: 09 04 00 00` (Format `CF_LOCALE`: `0x0409` - English US)
     * No text (`CF_TEXT` / `CF_UNICODETEXT`) data payload present.
5. **Interpretation:**  
   The challenge author left this note as a dual hint: it acknowledges that the legacy Volatility `clipboard` plugin executes properly, but explicitly advises the investigator that looking for the flag in clipboard memory is futile.
6. **Limitations:**  
   Clipboard contents reflect only what was stored in the system clipboard at capture time; earlier clipboard entries overwritten during the session cannot be retrieved.
7. **Confidence & Reasoning:**  
   **High.** The Volatility 2 plugin execution confirmed the exact technical behavior described in the note.

---

### 6.4 Finding F-002 & F-003: Memory Acquisition Provenance and Dual User Session Architecture
1. **What was found:**  
   The memory image was created via `DumpIt.exe` running under user `eminem` (Session 1), while a secondary user account `SlimShady` was actively logged into Session 2.
2. **Evidence source:**  
   * `windows.pslist`, `windows.psscan`, `windows.cmdline`, `windows.envars`
   * Handle table for PID 2624 (`windows.handles --pid 2624`)
   * Registry hives: `NTUSER.DAT` at `0xf8a001a1c010` (eminem) and `0xf8a0021aa410` (SlimShady)
3. **Discovery method:**  
   Enumerated process tree, inspected environment variable blocks (`HOMEPATH`, `USERNAME`), examined open handle descriptors, and analyzed UserAssist registry execution timestamps.
4. **Supporting evidence:**  
   * `DumpIt.exe` (PID 2624, PPID 1944) executed at `2019-06-29 07:29:25 UTC` with command line `"C:\Users\eminem\Desktop\DumpIt\DumpIt.exe"`.
   * Handle `0x20` in PID 2624 held open access to `\Device\PhysicalMemory`, while the target output file `2PAC-20190629-072925.raw` was created on eminem's Desktop.
   * Session 2 initialization occurred at `07:29:30 UTC` (`winlogon.exe` PID 2728), launching `explorer.exe` (PID 3012) and `StikyNot.exe` (PID 2432) under `\Users\SlimShady`.
   * `LogonUI.exe` (PID 2148) terminated at `07:29:59 UTC`, exactly 1 second before the kernel timestamp (`07:30:00 UTC`).
5. **Interpretation:**  
   This establishes complete forensic provenance for the memory image (`MemoryDump_Lab4_Copy.raw`). The machine `2PAC` was being operated by user `eminem` when DumpIt was executed, while `SlimShady`'s session was concurrently loaded in the background.
6. **Limitations:**  
   Memory forensics shows concurrent session presence but cannot definitively determine whether the two accounts represent physical user switching, fast user switching, or remote desktop logon without security event logs (Event ID 4624).
7. **Confidence & Reasoning:**  
   **High.** Parent-child process relationships, environment blocks, open kernel object handles, and process creation/termination timestamps perfectly align.

---

## 7. Updated Forensic Timeline

The timeline below integrates internal RAM snapshot timestamps (recorded in UTC) and analyst examination timestamps (recorded in ICT / UTC+7). Every timeline event is linked directly to forensic finding IDs.

| Event # | Timestamp | Timezone | Source Evidence | Linked Finding ID | Event Summary & Analytical Meaning |
|---|---|---|---|---|---|
| 1 | 2019-06-25 17:46:53 | UTC | `galf.lnk` metadata | F-004 | File `galf.jpeg` created/modified on eminem's Desktop (steganographic decoy carrier). |
| 2 | 2019-06-27 12:43:13 | UTC | UserAssist registry | F-007 | User `SlimShady` executes `Sticky Notes` application (`StikyNot.exe`). |
| 3 | 2019-06-27 18:14:13 | UTC | `Important.lnk` | F-005, F-011 | File `Important.txt` created on SlimShady's Desktop. |
| 4 | 2019-06-27 18:26:12 | UTC | `Important.lnk` / MFT | F-005, F-011 | File `Important.txt` modified (length: 153 B); subsequently deleted, but MFT record preserved in RAM paging pool. |
| 5 | 2019-06-27 18:26:50 | UTC | `Flag not here.lnk` | F-008 | Shortcut `Flag not here.lnk` created pointing to `Flag not here.bmp` (anti-forensic decoy). |
| 6 | 2019-06-29 07:28:07 | UTC | `windows.pslist` | F-001 | Host `2PAC` system boot sequence begins (`System` PID 4, `smss.exe` PID 256). |
| 7 | 2019-06-29 07:28:44 | UTC | `windows.pslist` | F-003 | User `eminem` logs in; Session 1 `explorer.exe` (PID 1944) begins. |
| 8 | 2019-06-29 07:29:25 | UTC | `windows.pslist`, `handles` | F-002 | `DumpIt.exe` (PID 2624) launched by eminem to acquire physical memory image. |
| 9 | 2019-06-29 07:29:30 | UTC | `windows.pslist` | F-003 | Session 2 initialized (`winlogon.exe` PID 2728, `csrss.exe` PID 2700). |
| 10 | 2019-06-29 07:29:36 | UTC | `windows.pslist` | F-003 | User `SlimShady` Session 2 `explorer.exe` (PID 3012) starts. |
| 11 | 2019-06-29 07:29:37 | UTC | `windows.pslist` | F-007 | `StikyNot.exe` (PID 2432) launched in SlimShady session. |
| 12 | 2019-06-29 07:29:59 | UTC | `windows.psscan` | F-009 | `LogonUI.exe` (PID 2148) terminates as SlimShady desktop initialization finishes. |
| 13 | 2019-06-29 07:30:00 | UTC | `windows.info` | F-001 | Exact internal kernel snapshot capture timestamp. |
| 14 | 10 ส.ค. 2569 16:05 | ICT | Submission 3 log | F-001 | Initial SHA-256 integrity baseline computed by Group 3 analyst. |
| 15 | 23 Aug 2026 13:19 | ICT | Method Log #2–8 | F-001–F-010 | Volatility 3 deep-analysis sweep (`psscan`, `cmdline`, `envars`, `malfind`, `netscan`). |
| 16 | 23 Aug 2026 13:20 | ICT | Method Log #20–28 | F-004, F-005, F-007 | Artefact extraction completed for `galf.jpeg`, `.lnk` files, and `StickyNotes.snt`. |
| 17 | 13 Sep 2026 08:46 | ICT | Method Log #36 | F-004, F-008 | Extracted hidden Steghide payload `LMAO.txt` from `galf.jpeg` using empty passphrase `""`. |
| 18 | 13 Sep 2026 08:49 | ICT | Method Log #37–38 | F-007, F-012 | Evaluated clipboard plugins across Volatility 3 and Volatility 2; verified clipboard held only locale `0x0409`. |
| 19 | 13 Sep 2026 08:49 | ICT | Method Log #39 | F-005, F-011 | Physical RAM carving located resident MFT record at offset `1004055552`; successfully extracted `Important.txt` and flag. |
| 20 | 13 Sep 2026 08:50 | ICT | Method Log #40 | F-004, F-011 | Cryptographic hash calculation (MD5/SHA-256) completed for `LMAO.txt` and `Important.txt`. |

---

## 8. Hypothesis Evaluation

Based on the empirical evidence gathered across all analysis stages, the preliminary hypotheses from Submission 3 are re-evaluated:

| Hypothesis ID | Original Hypothesis Statement | Status After Deep Analysis | Forensic Evaluation & Supporting Evidence | Unresolved Factors / Next Verification Steps |
|---|---|---|---|---|
| **H-001** | `galf.jpeg` / `galf.lnk` is the disguised flag file (spelled backwards). | **Refuted / Reclassified as Anti-Forensic Decoy** | **Refuted.** While `galf.jpeg` contains an embedded Steghide file (`LMAO.txt`), extracting it with an empty passphrase revealed the decoy string: *"Move on bro, there is nothing here :)"*. The reverse-name file was designed to misdirect investigators away from the true evidence. | No further action required; decoy payload fully cataloged and hashed. |
| **H-002** | `DumpIt.exe` was executed by user `eminem` to self-acquire memory dump. | **Supported (Confirmed)** | **Confirmed.** PID 2624 was executed by user `eminem` from `C:\Users\eminem\Desktop\DumpIt\DumpIt.exe`. Handles confirm read access to `\Device\PhysicalMemory` and write streaming to `2PAC-20190629-072925.raw`. | Event log corroboration (Event ID 4688) would confirm command elevation. |
| **H-003** | `SlimShady`'s account is directly involved as a victim/compromised profile, and `Important.txt` holds critical stolen/deleted data. | **Supported (Definitively Confirmed)** | **Confirmed.** The deleted file `Important.txt` was located on SlimShady's Desktop. Targeted memory carving recovered the resident MFT record (`0x3bd8ac00`), extracting the intact 153-byte document containing the authentic flag: `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`. | None. Hypothesis is 100% verified and the primary investigation goal is achieved. |

---

## 9. Fact / Inference / Hypothesis Separation

To maintain strict evidentiary integrity, all conclusions in this report are categorized into three distinct tiers:

### 9.1 Facts (Directly observed in tool outputs)
* The memory image is from a Windows 7 SP1 64-bit system (build 7601.17514) on host `2PAC`.
* The RAM dump was captured at internal timestamp `2019-06-29 07:30:00 UTC`.
* `DumpIt.exe` (PID 2624) was executed by `eminem` at `07:29:25 UTC` and opened `\Device\PhysicalMemory`.
* Two user sessions were active: Session 1 (`eminem`) and Session 2 (`SlimShady`).
* `galf.jpeg` was dumped from offset `0x3e8ad250` (MD5: `65184fca05a4f6fdcfa68eb586a7f969`) and yielded `LMAO.txt` (38 B, MD5: `24b2f7c3998a603c51394dc0736d37cb`) with content *"Move on bro, there is nothing here :)"* using an empty passphrase (`""`).
* `Important.txt` existed on SlimShady's Desktop (length: 153 B). Active file cache streaming was unmapped, but the resident MFT record survived at physical offset `1004055552` (`0x3bd8ac00`).
* Carving the resident `$DATA` attribute extracted the 153-byte `Important.txt` (MD5: `3b07cd60cbfc3ea0f41adcaf9824e27c`), revealing the flag: `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`.
* `StickyNotes.snt` was dumped from offset `0x3fd40910` and contains the text: *"The clipboard plugin works well but it doesn't give the flag :P"*.
* Volatility 3 v2.28.0 lacks a native `windows.clipboard` plugin; Volatility 2.6.1 executed the clipboard plugin and confirmed the clipboard contained only locale identifier `0x0409` (en-US).
* Volatility 3 `filescan` outputs kernel virtual addresses of `FILE_OBJECT` structures; Item 19's initial command failed because a physical offset was mistakenly supplied to `--virtaddr`.
* No active remote network sockets were established to external IP addresses at capture time.

### 9.2 Inferences (Logical conclusions derived from facts)
* `Important.txt` was deleted prior to memory acquisition, causing the operating system cache manager to purge its cached pages from active file streams, while the filesystem driver retained the MFT record in physical RAM.
* Because NTFS stores files under ~700 bytes as resident attributes directly inside the 1024-byte MFT record, the full content of `Important.txt` survived uncorrupted in unallocated memory paging pool.
* `galf.jpeg` (Joker image with `LMAO.txt`), `Flag not here.lnk`, `Screenshot1.png` (*"This is a good lie and all but it won't help you :P"*), and the `StickyNotes.snt` note were part of a deliberate, coordinated anti-forensic deception framework designed to mislead automated triage tools and human investigators.
* The `PAGE_EXECUTE_READWRITE` VAD regions flagged by `malfind` in `dllhost.exe` and `explorer.exe` represent GDI+/COM thumbnail rendering buffers rather than malicious code injection.
* The system was operating under VirtualBox virtualization, evidenced by active `VBoxService.exe` and `VBoxTray.exe` processes and the `10.0.2.15` network adapter.

### 9.3 Hypotheses (Unproven assumptions requiring additional evidence)
* The compromise and subsequent file deletion may have been carried out via an interactive console session or automated local script rather than remote network exploitation.
* The memory acquisition via DumpIt may have been performed by the user immediately after discovering the compromise, accounting for the rapid succession of events prior to capture.

---

## 10. Limitations

Memory forensic analysis provides unmatched insight into volatile state but operates within defined forensic constraints:

1. **Volatile Temporal Window:** RAM captures preserve only state present at `2019-06-29 07:30:00 UTC`. Processes or network connections that terminated and whose memory structures were overwritten prior to capture cannot be recovered.
2. **Purged Active Cache vs. Resident MFT Survival:** When files are deleted from NTFS, active file cache buffers are purged. While resident files (<700 bytes) survive inside MFT records, non-resident deleted files (>700 bytes) would require disk cluster carving.
3. **Absence of Packet Capture (PCAP):** Without network packet captures, prior data exfiltration over closed connections cannot be definitively ruled out from `netscan` alone.
4. **Tool Architectural & Framework Discrepancies:** Volatility 3 does not implement all legacy plugins (e.g., `windows.clipboard`), necessitating multi-framework validation using Volatility 2 for legacy subsystem inspection.
5. **No Event Log Correlation:** Operating system security event logs (e.g. `Security.evtx` Event IDs 4624, 4688) are unparsed in raw memory, preventing exact attribution of whether session switching was physical or remote.

---

## 11. Preparation for Draft Forensic Report (Submission 5)

The deep analysis findings established in this report provide complete evidentiary resolution for the final forensic report (Submission 5).

* **Confirmed Findings Ready for Submission 5:**
  * Complete OS baseline, memory timeline, and verified chain-of-custody hashes.
  * Verified memory acquisition provenance linking `DumpIt.exe` to `2PAC-20190629-072925.raw`.
  * Complete user session reconstruction (eminem & SlimShady).
  * Resolution of anti-forensic red herrings: extraction and hashing of `galf.jpeg` (`LMAO.txt`), `Screenshot1.png`, and `Flag not here.lnk`.
  * Technical verification of the clipboard subsystem confirming the accuracy of the Sticky Notes hint.
  * **Definitive case resolution:** Physical memory MFT carving of deleted file `Important.txt` (153 bytes) and recovery of the authentic competition flag: `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`.
* **Pending Actions for Final Submission:**
  * Insertion of high-resolution tool screenshots (`Pstree.png`, `Netscan.png`, `Malfind.png`, `UserAssist.png`, `HexCarve_Important.png`) into the final formatted document.
  * Compilation of executive summary and technical recommendations for remediation.

---

## 12. Appendix

### 12.1 Raw Command Outputs Inventory (`deep_analysis/raw_output/`)
* `01_windows.info.txt` — Full operating system kernel details, build lab string, and snapshot timestamp.
* `02_windows.pslist.txt` — Complete active process listing.
* `03_windows.psscan.txt` — Pool-scanned processes including unlinked/terminated objects.
* `04_windows.cmdline.txt` — Complete process command-line arguments.
* `05_windows.envars.txt` — Process environment variables and user contexts.
* `06_windows.malfind.txt` — RWX VAD code injection scan output.
* `07_windows.netscan.txt` — Network endpoints and listening sockets.
* `08_windows.dlllist_pid2624.txt` & `09_windows.handles_pid2624.txt` — DLLs and handles for `DumpIt.exe`.
* `10_windows.dlllist_pid2432.txt` & `11_windows.handles_pid2432.txt` — DLLs and handles for `StikyNot.exe`.
* `12_windows.dlllist_pid1944.txt` & `13_windows.handles_pid1944.txt` — DLLs and handles for `explorer.exe` (eminem).
* `14_windows.dlllist_pid3012.txt` & `15_windows.handles_pid3012.txt` — DLLs and handles for `explorer.exe` (SlimShady).
* `16_windows.registry.hivelist.txt` — Memory registry hive base addresses.
* `17_windows.registry.userassist.txt` — Decoded UserAssist execution counts and timestamps.
* `18_windows.dlllist_pid1688.txt` & `19_windows.handles_pid1688.txt` — Inspection for `SearchFilterHost.exe`.
* `20_windows.dlllist_pid2076.txt` & `21_windows.handles_pid2076.txt` — Inspection for `dllhost.exe`.
* `22_windows.clipboard.txt` — Volatility 3 invocation failure and Volatility 2 clipboard execution verification.
* `23_steghide_extract_galf.txt` — Steghide payload extraction of `LMAO.txt` with empty passphrase.
* `24_carve_important_txt.txt` — Memory carving records, resident MFT discovery at offset `0x3bd8ac00`, and extracted flag content.
* `strings_*.txt` — Plaintext strings extracted from all dumped artefacts.

### 12.2 Extracted Artefacts Inventory & Hashes (`deep_analysis/hashes.md`)

| File Name | File Type | File Size | MD5 Hash | SHA-256 Hash |
|---|---|---|---|---|
| `file.0x3e8a85b0.0xfa80022ab770.DataSectionObject.Flag not here.lnk.dat` | MS Windows Shortcut (.lnk) | 4,096 B | `0b825e446f027ce37bf5234554a299d1` | `357c5a527c1d13511ed8efe106ade1b40d3f1874fb7ca9f6878af3caa4f5c11b` |
| `file.0x3e8ad250.0xfa80022ad0f0.DataSectionObject.galf.jpeg.dat` | JPEG Image (Steghide carrier) | 229,376 B | `65184fca05a4f6fdcfa68eb586a7f969` | `f2fd251f985784ce6307b3127ba233f9a85d8dacd8f1eb1957a51290a37a3bc1` |
| `file.0x3e8d19e0.0xfa80022d1670.DataSectionObject.Screenshot1.png.dat` | PNG Image | 57,344 B | `4fb7a74bb4387d44d80c13b1d56de81e` | `ffa9cfe5460bda0f02de09ffc8dda78ae5b23ce1771f14e9d8de6585c360b6cb` |
| `file.0x3e8d1c80.0xfa80022bd7b0.DataSectionObject.galf.lnk.dat` | MS Windows Shortcut (.lnk) | 4,096 B | `5ea67ed7eeedced8b9ae24e5185df6d8` | `3d210acc182fbf3c53ee7a1c6a5b0081d37cb3c0dbdcbd06b7c81fe178aa9bee` |
| `file.0x3e8e5ba0.0xfa80022e54b0.DataSectionObject.Screenshot1.lnk.dat` | MS Windows Shortcut (.lnk) | 4,096 B | `ceb4fc5bc521d693fd7a673c97e3ef83` | `d265b72ccb5541c3b7b7c3bacbfacf485b2728fec39970059da17bc021d898af` |
| `file.0x3f939720.0xfa80013f7e40.DataSectionObject.Important.lnk.dat` | MS Windows Shortcut (.lnk) | 4,096 B | `60d85bb5b1ef50236f15203d89fd981b` | `01e79afe39bd7fad780a88ca3daab49de92b0d77ae3602e79c30b5e6eb1d2c26` |
| `file.0x3fd40910.0xfa8000f40590.DataSectionObject.StickyNotes.snt.dat` | OLE Compound Document | 4,096 B | `bb18b759aecd143d9620339a85042e4a` | `98e9ff347b46f9f87801e34d53267ea711dd816304cd5e900f0cb521548dc5ff` |
| `LMAO.txt` | ASCII Text (Steghide Decoy) | 38 B | `24b2f7c3998a603c51394dc0736d37cb` | `9a1ec67f5e3f22bc6c445709568d42ad0aa2df4af96898d71a1c7c3cff9dee70` |
| `Important.txt` | ASCII Text (Carved Flag File) | 153 B | `3b07cd60cbfc3ea0f41adcaf9824e27c` | `352b436ea0ee449631985c10e1610f124fa99e46583b1c7e8b0f7122b7b42708` |

*Note: High-resolution screenshots of command outputs and forensic tool windows will be inserted manually into the finalized `.docx`/`.pdf` submission by the Group 3 Report Lead.*

---

## 13. Closing Reflection

The deep analysis phase concluded with complete investigative resolution of the MemLabs Lab 4 scenario. By looking beyond surface-level active file streaming, the investigation successfully bypassed a sophisticated series of anti-forensic diversions (`galf.jpeg`, `Flag not here.lnk`, `Screenshot1.png`, and the clipboard clue in `StickyNotes.snt`) and definitively solved the case. Extracting `LMAO.txt` from `galf.jpeg` using an empty passphrase proved that the reverse-named file was an intentional distraction. More importantly, understanding NTFS resident file structures allowed the recovery of `Important.txt` (153 bytes) directly from an in-memory MFT record at physical offset `1004055552` (`0x3bd8ac00`), recovering the competition flag `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`. Hypothesis H-002 (memory acquisition via DumpIt) and Hypothesis H-003 (SlimShady account holding the deleted critical evidence) stand fully confirmed, while Hypothesis H-001 was refuted as a decoy. These definitive findings, complete with verified cryptographic hashes and technical MFT parsing records, provide an airtight foundation for the Submission 5 Final Forensic Investigation Report.
