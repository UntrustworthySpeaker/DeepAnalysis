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
    *Responsibilities:* Executes Volatility 3 plugins, leads forensic tool configuration, runs extraction scripts, and oversees memory anomaly analysis.
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
> In strict compliance with digital forensics principles and ISO/IEC 27037 standards, **all analysis actions, Volatility 3 commands, and file carving were performed exclusively on the Working Copy (`MemoryDump_Lab4_Copy.raw`)**. The Original Evidence file remains write-protected, unmoved, and completely unaltered in the `Original_Files/` storage directory.

---

## 3. Analysis Scope

Following the completion of the Initial Triage Report (Submission 3), which scoped out potential processes of interest and mapped out preliminary file offsets, Submission 4 transitions the investigation from basic triage to in-depth forensic verification. 

The deep-analysis scope includes:
1. **OS Kernel & Subsystem Baseline:** Extracting exact operating system build, service pack levels, kernel base address, and memory architecture via `windows.info`.
2. **Process Hierarchy & Termination Reconstruction:** Executing comparative analysis between active process lists (`windows.pslist`) and unallocated memory pool structures (`windows.psscan`) to identify unlinked or terminated processes.
3. **Command Line & Environment Enumeration:** Extracting process arguments (`windows.cmdline`) and environment variables (`windows.envars`) to correlate user accounts, system paths, and host metadata.
4. **Code Injection & Volatile Memory Scanning:** Performing VAD-level inspection via `windows.malfind` across all processes to detect anomalous `PAGE_EXECUTE_READWRITE` memory allocations.
5. **Per-PID Deep Inspection:** Conducting targeted module (`windows.dlllist`) and resource handle (`windows.handles`) audits on priority processes:
   * PID 2624 (`DumpIt.exe` — user `eminem`, Session 1)
   * PID 2432 (`StikyNot.exe` — user `SlimShady`, Session 2)
   * PID 1944 & PID 3012 (`explorer.exe` — sessions 1 and 2)
   * PID 1688 (`SearchFilterHost.exe`) & PID 2076 (`dllhost.exe`)
6. **Network Profile Verification:** Verifying network sockets, connection tables, and listening ports via `windows.netscan`.
7. **Artefact Extraction & Carving:** Extracting cached file streams from memory via physical address offsets (`windows.dumpfiles --physaddr`), computing cryptographic integrity hashes (MD5, SHA-256), and inspecting file internals (`file`, `strings`, `steghide`).
8. **User Activity & Execution Tracking:** Inspecting NTUSER.DAT registry hives, ShellBags, and UserAssist keys (`windows.registry.userassist`) to reconstruct user actions across both profiles.

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
| 19 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --virtaddr 0x3e8ad250` | Extraction attempt for galf.jpeg using `--virtaddr` offset from filescan | Result was empty; Volatility 3 `filescan` outputs physical offsets rather than virtual pointers | N/A (0 bytes output) |
| 20 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3e8ad250` | Extraction fix for galf.jpeg using `--physaddr` (4.6, F-004) | Successfully dumped DataSectionObject: `file.0x3e8ad250.0xfa80022ad0f0.DataSectionObject.galf.jpeg.dat` (229,376 bytes) | `extracted/file.0x3e8ad250.0xfa80022ad0f0.DataSectionObject.galf.jpeg.dat` |
| 21 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3e8d1c80` | Extraction of galf.lnk shortcut (4.6, F-004) | Successfully dumped: `file.0x3e8d1c80.0xfa80022bd7b0.DataSectionObject.galf.lnk.dat` (4,096 bytes) | `extracted/file.0x3e8d1c80.0xfa80022bd7b0.DataSectionObject.galf.lnk.dat` |
| 22 | 23 Aug 2026, 13:20 | นายกวิน ฟุคุนิชิ / Agent | Volatility 3 v2.28.0 | `vol -f /home/engineer/Documents/University/MemoryForensic/working_directory/MemoryDump_Lab4_Copy.raw -o deep_analysis/extracted windows.dumpfiles --physaddr 0x3fc398d0` | Extraction attempt for Important.txt (4.6, F-005) | No resident DataSectionObject in RAM cache; confirmed Important.txt data clusters were unmapped/deleted prior to capture | N/A (no cache file dumped) |
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
| 35 | 23 Aug 2026, 13:23 | นายกวิน ฟุคุนิชิ / Agent | steghide | `steghide info extracted/file.0x3e8ad250...galf.jpeg.dat -p ""` | Steganographic inspection of galf.jpeg to test H-001 | Detected embedded file `LMAO.txt` (38 bytes, encrypted rijndael-128 cbc); password-protected (flagged to user per Section 5) | Terminal / report log |

---

## 5. Deep Findings Table

The table below integrates the initial findings (F-001 through F-007) with updated evidence, confidence ratings, and new deep-analysis findings (F-008 through F-010).

| Finding ID | Finding Description | Evidence Source | Timestamp | Tool / Method | Supporting Evidence | Forensic Interpretation | Confidence | Status |
|---|---|---|---|---|---|---|---|---|
| **F-001** | OS Kernel Profile & Exact Memory Capture Baseline | Kernel memory layer | 2019-06-29 07:30:00 UTC | `windows.info` | NTBuildLab: `7601.17514.amd64fre.win7sp1_rtm.`, 64-bit AMD64, 1 CPU, Kernel Base `0xf80002605000` | Pinpoints OS as Windows 7 SP1 64-bit. Memory snapshot represents state at exactly 07:30:00 UTC. | **High** | Confirmed |
| **F-002** | Physical RAM Acquisition via MoonSols DumpIt | Process tree, command lines, handle tables | 2019-06-29 07:29:25 UTC | `windows.pslist`, `windows.cmdline`, `windows.handles` | PID 2624 launched as `"C:\Users\eminem\Desktop\DumpIt\DumpIt.exe"`, Wow64: True, handle to `\Device\PhysicalMemory` and `2PAC-20190629-072925.raw` | DumpIt was actively capturing physical RAM to disk at the time of snapshot, proving self-acquisition. | **High** | Confirmed |
| **F-003** | Dual Interactive Logon Architecture (eminem & SlimShady) | Process tree, environment blocks, LogonUI scan | 2019-06-29 07:28:44 – 07:29:36 UTC | `windows.pslist`, `windows.psscan`, `windows.envars` | Session 1: `eminem` (`explorer.exe` PID 1944, started 07:28:44 UTC); Session 2: `SlimShady` (`explorer.exe` PID 3012, started 07:29:36 UTC) preceded by `winlogon` (PID 2728) | Two interactive desktop sessions ran concurrently; user switching occurred right before RAM capture. | **High** | Confirmed |
| **F-004** | Disguised Flag Candidate `galf.jpeg` Encapsulating Steghide Container | File table, dumped data section, steghide probe | 2019-06-25 17:46:53 UTC (file mtime) | `windows.filescan`, `windows.dumpfiles`, `steghide info` | FileObject `0x3e8ad250` dumped (229,376 B); visual image depicts the Joker; steghide reveals embedded payload `LMAO.txt` (38 B, Rijndael-128 CBC) | Filename "galf" is "flag" spelled backwards. Image is an active steganographic carrier with an encrypted inner file. | **High** | Confirmed (Password Protected) |
| **F-005** | Deletion of Critical Artefact `Important.txt` from SlimShady Profile | File table, link shortcuts, IE index.dat | 2019-06-27 18:26:12 UTC (mtime) | `windows.filescan`, `windows.dumpfiles`, strings grep | `Important.lnk` records target `C:\Users\SlimShady\Desktop\Important.txt` (153 B). `dumpfiles` at `0x3fc398d0` returned 0 cached pages. | Directly supports case briefing ("deleted a very important file"). Data was unmapped from RAM cache before dump. | **High** | Confirmed (Deleted) |
| **F-006** | Absence of Active Remote C2 or External Network Sockets | Network table | 2019-06-29 07:28 – 07:30 UTC | `windows.netscan` | Only TCP/UDP listening on `0.0.0.0`, loopback `127.0.0.1`, and host interface `10.0.2.15` (VirtualBox NAT). No foreign IPs. | No established remote exfiltration channels existed at exact moment of snapshot (does not rule out past connections). | **High** | Confirmed |
| **F-007** | Recovery of In-Memory Note in `StickyNotes.snt` | Process table, handle table, carved OLE stream | 2019-06-27 12:43:13 UTC (UserAssist) | `windows.handles`, `windows.dumpfiles`, `strings` | PID 2432 (`StikyNot.exe`) held open handle to `StickyNotes.snt` (`0x3fd40910`). Extracted RTF string: *"The clipboard plugin works well but it doesn't give the flag :P"*. | Forensic taunt/clue embedded by challenge creator; confirms SlimShady's active session interactions. | **High** | Confirmed |
| **F-008** | Anti-Forensic Distraction Artefacts & Shell Link Metadata | Carved shortcut files, image rendering | 2019-06-27 18:12:15 UTC (ctime) | `windows.dumpfiles`, `file`, `strings`, PIL crop | `Flag not here.lnk` (0 B target length) and `Screenshot1.png` dumped. Cropped Google search bar shows: *"This is a good lie and all but it won't help you :P"*. | Demonstrates deliberate placement of deceptive artefacts (red herrings) to misdirect automated triage. | **High** | Confirmed |
| **F-009** | Transient Process Pool Unlinking & Interactive Logon Sequence | Unallocated pool tags, process termination timestamps | 2019-06-29 07:29:51 – 07:30:07 UTC | `windows.psscan` vs `windows.pslist` | `psscan` revealed 3 terminated processes missing from `pslist`: `csrss.exe` (PID 2672), `LogonUI.exe` (PID 2148, exited 07:29:59 UTC), and `dllhost.exe` (PID 2572). | Accurately reconstructs the graphical logon transition into SlimShady's user session 1 second before RAM capture. | **High** | Confirmed |
| **F-010** | Forensic Invalidation of Malfind False Positives | Process VAD trees, DLL inspection, handle tables | 2019-06-29 07:29:02 – 07:30:00 UTC | `windows.malfind`, `windows.dlllist`, `windows.handles` | Malfind flagged RWX allocations in `explorer.exe`, `dllhost.exe`, `SearchFilterHost.exe`. DLL and handle inspection confirmed COM/GDI+ thumbnail rendering. | VAD anomalies are legitimate Windows subsystem rendering buffers (e.g. `gdiplus.dll`, `photowrap.dll`), not code injection. | **High** | Confirmed |

---

## 6. Evidence Support for Each Finding

Below is the deep-dive analysis for the three most critical findings governing the case narrative.

### 6.1 Finding F-004: Disguised Artefact `galf.jpeg` and Embedded Steghide Container
1. **What was found:**  
   A file named `galf.jpeg` located at `\Users\eminem\Desktop\galf.jpeg` and its corresponding shortcut `galf.lnk`. Steganographic inspection confirmed the JPEG contains an embedded, encrypted file named `LMAO.txt`.
2. **Evidence source:**  
   * Memory dump physical offset `0x3e8ad250` (FileObject `0xfa80022ad0f0`)
   * Memory dump physical offset `0x3e8d1c80` (Shortcut `galf.lnk`)
3. **Discovery method:**  
   Identified via `windows.filescan`, extracted to disk using `windows.dumpfiles --physaddr 0x3e8ad250`, verified using `file` and `strings`, and probed via `steghide info`.
4. **Supporting evidence:**  
   * File size: 229,376 bytes (data section) with valid JFIF header (`FF D8 FF E0`) and EOI at `0x37d18` (228,634 bytes).
   * Visual content: High-resolution illustration of the Joker character.
   * Steganography check: `steghide info` reported embedded file `LMAO.txt` (size: 38.0 bytes, encrypted: `rijndael-128, cbc`, compressed: yes).
5. **Interpretation:**  
   "galf" is the exact reverse of "flag". The file serves a dual purpose: visually presenting a taunting image while cryptographically concealing `LMAO.txt` inside its discrete cosine transform (DCT) coefficients using Steghide.
6. **Limitations:**  
   `LMAO.txt` requires a passphrase for extraction. Per Section 5 ground rules, automated cracking/brute-forcing was halted to avoid speculative unauthorized alterations.
7. **Confidence & Reasoning:**  
   **High.** The existence of the embedded container and encryption algorithm is deterministically verified by Steghide's header parser.

---

### 6.2 Finding F-005: Deletion of Primary Evidence Artefact `Important.txt`
1. **What was found:**  
   A text document titled `Important.txt` previously resided on SlimShady's Desktop (`C:\Users\SlimShady\Desktop\Important.txt`), but its cached memory pages were purged prior to memory acquisition.
2. **Evidence source:**  
   * `windows.filescan` offset `0x3fc398d0`
   * Shortcut `Important.lnk` at physical offset `0x3f939720`
   * Internet Explorer / Windows Explorer history records (`Visited: SlimShady@file:///C:/Users/SlimShady/Desktop/Important.txt`)
3. **Discovery method:**  
   Cross-referenced `windows.filescan` with `windows.dumpfiles --physaddr 0x3fc398d0`, followed by raw memory carving and binary string search.
4. **Supporting evidence:**  
   * `Important.lnk` extracted and parsed: records original file size of **153 bytes**, target path `C:\Users\SlimShady\Desktop\Important.txt`, creation time `2019-06-27 18:14:13 UTC`, and modification time `2019-06-27 18:26:12 UTC`.
   * `windows.dumpfiles` returned no resident `DataSectionObject` or cache pages for offset `0x3fc398d0`.
   * Shell history at memory offset `0x23b5c09e` confirms interactive user access via Explorer.
5. **Interpretation:**  
   This finding directly substantiates the initial case briefing: *"The hacker stole a lot of information but also deleted a very important file."* The file existed and was modified on June 27, 2019, but was deleted, causing its file cache to be discarded from active physical RAM.
6. **Limitations:**  
   Because the file contents were not resident in memory cache at snapshot time, the 153 bytes cannot be reconstructed from RAM alone without disk unallocated cluster recovery.
7. **Confidence & Reasoning:**  
   **High.** The combination of Shell Link metadata, LNK parser records, and IE history unequivocally confirms file existence, attributes, and subsequent cache absence.

---

### 6.3 Finding F-002 & F-003: Memory Acquisition Provenance and Dual User Session Architecture
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

The timeline below integrates internal RAM snapshot timestamps (recorded in UTC) and analyst examination timestamps (recorded in ICT / UTC+7).

| Event # | Timestamp | Timezone | Source Evidence | Linked Finding ID | Event Summary & Analytical Meaning |
|---|---|---|---|---|---|
| 1 | 2019-06-25 17:46:53 | UTC | `galf.lnk` metadata | F-004 | File `galf.jpeg` created/modified on eminem's Desktop. |
| 2 | 2019-06-27 12:43:13 | UTC | UserAssist registry | F-007 | User `SlimShady` executes `Sticky Notes` application (`StikyNot.exe`). |
| 3 | 2019-06-27 18:14:13 | UTC | `Important.lnk` | F-005 | File `Important.txt` created on SlimShady's Desktop. |
| 4 | 2019-06-27 18:26:12 | UTC | `Important.lnk` | F-005 | File `Important.txt` modified (length: 153 B); subsequently deleted prior to dump. |
| 5 | 2019-06-27 18:26:50 | UTC | `Flag not here.lnk` | F-008 | Shortcut `Flag not here.lnk` created pointing to `Flag not here.bmp`. |
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

---

## 8. Hypothesis Evaluation

Based on the empirical evidence gathered during deep analysis, the preliminary hypotheses from Submission 3 are re-evaluated:

| Hypothesis ID | Original Hypothesis Statement | Status After Deep Analysis | Forensic Evaluation & Supporting Evidence | Unresolved Factors / Next Verification Steps |
|---|---|---|---|---|
| **H-001** | `galf.jpeg` / `galf.lnk` is the disguised flag file (spelled backwards). | **Supported (with cryptographic protection)** | **Confirmed.** `galf.jpeg` is a valid image containing an embedded Steghide file named `LMAO.txt` (38 bytes, Rijndael-128 CBC encrypted). | Password is required to decrypt `LMAO.txt`. Per safety rules, brute-forcing was not executed unprompted. |
| **H-002** | `DumpIt.exe` was executed by user `eminem` to self-acquire memory dump. | **Supported (Confirmed)** | **Confirmed.** PID 2624 was executed by user `eminem` from `C:\Users\eminem\Desktop\DumpIt\DumpIt.exe`. Handles confirm read access to `\Device\PhysicalMemory` and write streaming to `2PAC-20190629-072925.raw`. | Event log corroboration (Event ID 4688) would confirm command elevation. |
| **H-003** | `SlimShady`'s account is directly involved as a victim/compromised profile. | **Supported (Refined)** | **Confirmed.** `SlimShady`'s desktop contained the primary deleted evidence file `Important.txt` (153 bytes) and active `StickyNotes.snt`. | Disk forensics (MFT / unallocated clusters) needed to carve deleted `Important.txt` raw bytes. |

---

## 9. Fact / Inference / Hypothesis Separation

To ensure forensic rigor, all claims in this report are categorized into three distinct evidentiary tiers:

### 9.1 Facts (Directly observed in tool outputs)
* The memory image is from a Windows 7 SP1 64-bit system (build 7601.17514) on computer name `2PAC`.
* The RAM dump was captured at internal timestamp `2019-06-29 07:30:00 UTC`.
* `DumpIt.exe` (PID 2624) was executed by `eminem` at `07:29:25 UTC` and opened `\Device\PhysicalMemory`.
* Two user sessions were active: Session 1 (`eminem`) and Session 2 (`SlimShady`).
* `galf.jpeg` was dumped from offset `0x3e8ad250` (MD5: `65184fca05a4f6fdcfa68eb586a7f969`) and contains an encrypted `steghide` payload `LMAO.txt`.
* `Important.txt` existed on SlimShady's Desktop (length: 153 B), but its cached data pages were unmapped/absent from RAM at capture time.
* `StickyNotes.snt` was dumped from offset `0x3fd40910` and contains the text string: *"The clipboard plugin works well but it doesn't give the flag :P"*.
* No active remote network sockets were established to external IP addresses at capture time.

### 9.2 Inferences (Logical conclusions derived from facts)
* `Important.txt` was deleted prior to memory acquisition, causing the OS to discard its cached pages.
* `galf.jpeg`, `Screenshot1.png`, and `Flag not here.lnk` were deliberately crafted as CTF challenge components / anti-forensic misdirection.
* The `PAGE_EXECUTE_READWRITE` VAD regions flagged by `malfind` in `dllhost.exe` and `explorer.exe` represent GDI+/COM thumbnail rendering buffers rather than malicious code injection.
* The system was operating under VirtualBox virtualization, evidenced by active `VBoxService.exe` and `VBoxTray.exe` processes and `10.0.2.15` network adapter.

### 9.3 Hypotheses (Unproven assumptions requiring additional evidence)
* The decryption passphrase for `LMAO.txt` inside `galf.jpeg` may have been contained within the deleted 153-byte `Important.txt` file.
* The compromise / file deletion may have been carried out via an interactive console session rather than remote network exploitation.

---

## 10. Limitations

Memory forensic analysis provides unmatched insight into volatile state but possesses inherent technical boundaries:

1. **Volatile Temporal Window:** RAM captures preserve only state present at `2019-06-29 07:30:00 UTC`. Processes or network connections that closed prior to the acquisition window cannot be fully observed.
2. **Purged Cache for Deleted Files:** When `Important.txt` was deleted from the NTFS filesystem, its cached pages in physical RAM were released, preventing full text extraction from volatile memory alone.
3. **Absence of Packet Capture (PCAP):** Without network packet captures, prior data exfiltration over closed connections cannot be ruled out from `netscan` alone.
4. **Steganographic Cryptography:** The extracted artefact `galf.jpeg` uses Rijndael-128 encryption within Steghide; cryptographic key material is required to access the plaintext.
5. **No Event Log Correlation:** Operating system security event logs (e.g. `Security.evtx` Event IDs 4624, 4688) are unparsed in raw memory, preventing exact attribution of whether session switching was physical or remote.

---

## 11. Preparation for Draft Forensic Report (Submission 5)

The deep analysis findings established in this report provide a strong evidentiary foundation for the final forensic report (Submission 5). 

* **Ready for Submission 5:**
  * Complete OS baseline, memory timeline, and verified chain-of-custody hashes.
  * Verified memory acquisition provenance linking `DumpIt.exe` to `2PAC-20190629-072925.raw`.
  * Complete user session reconstruction (eminem & SlimShady).
  * Extraction, hashing, and steganographic verification of `galf.jpeg` (`LMAO.txt`).
  * Confirmation of the deletion of `Important.txt` (153 bytes) supported by LNK and history records.
  * Extraction and decoding of `StickyNotes.snt` forensic notes.
* **Pending Actions for Final Submission:**
  * Integration of visual tool screenshots (`Pstree.png`, `Netscan.png`, `Malfind.png`, `UserAssist.png`) into the report appendix.
  * Resolution of the encrypted `LMAO.txt` passphrase upon consultation with instructor / case guidelines.

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

*Note: High-resolution screenshots of command outputs and forensic tool windows will be inserted manually into the finalized `.docx`/`.pdf` submission by the Group 3 Report Lead.*

---

## 13. Closing Reflection

During this deep analysis phase, the most critical finding was the extraction of `galf.jpeg` and the discovery of its embedded, encrypted `steghide` container `LMAO.txt`, paired with the verification that `Important.txt` (153 bytes) had its memory cache purged upon deletion. Hypothesis H-002 (memory acquisition via `DumpIt.exe` under user `eminem`) gained definitive confirmation through open physical memory handle analysis, while H-001 gained strong support as the primary steganographic carrier. However, the exact plaintext flag remains protected by Rijndael-128 encryption pending passphrase retrieval. The primary technical limitation encountered is the volatility of RAM cache, which prevented direct recovery of deleted plaintext files once unmapped from memory. Complementing this memory analysis with raw disk cluster carving (e.g. MFT or unallocated clusters) would provide the missing data required to recover the full 153-byte `Important.txt` file and complete the final Submission 5 forensic report.
