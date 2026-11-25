# Windows Forensics 1 Study Notes: Registry Forensics with Registry Explorer

IS 3033 · Operating Systems Security · TryHackMe *Windows Forensics 1* hands-on challenge

Each topic marks what came from the **lab material** (📘 Lab: the TryHackMe room, or my earlier IS 3033 Lab 4 notes) and what I learned beyond it (🔎 Beyond). Sources are at the end and screenshots linked above.

---

## 1. Why Autopsy couldn't read the SAM file

- What I saw: Autopsy listed `SAM` with every timestamp `0000-00-00 00:00:00`, and the Hex tab said "offset 0-16,384 could not be read."
- 🔎 Beyond: that means Autopsy couldn't read the file's contents at all. Windows keeps its **live** registry hives open and locked while it runs, so the VM's own `C:\Windows\System32\config\SAM` can't be read by other programs.
- 📘 Lab: the evidence is the **triage copy** collected from the suspect machine: `Desktop\triage\C\Windows\System32\config\`. The intended tool is **Registry Explorer** (EZTools folder on the Desktop).

---

## 2. Registry hives and where they live

- 📘 Lab: a hive is a group of keys, subkeys and values stored in one file on disk.

| Hive | File location | What I used it for |
|---|---|---|
| SAM | `C:\Windows\System32\config\SAM` | Local accounts, RIDs, password hints |
| SOFTWARE | `C:\Windows\System32\config\SOFTWARE` | Portable device friendly names |
| SYSTEM | `C:\Windows\System32\config\SYSTEM` | USB device history and timestamps, MountedDevices |
| NTUSER.DAT | `C:\Users\<user>\NTUSER.DAT` (hidden file) | That user's RecentDocs and UserAssist |

- 🔎 Beyond: **NTUSER.DAT becomes `HKEY_CURRENT_USER`** when that user logs in. Each user has their own, so per-user activity (files opened, programs run) is there. Machine-wide things (devices, accounts) are in the `config` hives.
- Hidden files such as NTUSER.DAT can be opened by typing the name into the File name box.

---

## 3. Transaction logs and "dirty" hives

- 📘 Lab: Registry Explorer warns that hives are dirty. Point it at the `.LOG1` and `.LOG2` files with the same name, and it builds a **clean** hive to analyze.
- 🔎 Beyond:
  - Windows doesn't always write changes straight into the hive file. It writes them first to **transaction logs** (journals) in the same folder, with the same name plus `.LOG`, `.LOG1` or `.LOG2`. Transaction logs date back to **Windows 2000**.
  - A hive is "dirty" when its header shows that not every pending change has been committed. The missing changes have to be replayed from the logs.
  - **Forensic risk:** the newest activity may exist **only** in the logs. If you skip the replay, you may analyze stale data.
- Flow:
  1. File → Load hive → pick the primary hive.
  2. Dirty warning → **Yes** → select **both** LOG1 and LOG2 (Shift-click).
  3. Save the clean hive → load the clean copy.
- ⚠️ In one load I **declined the replay and cancelled the save dialog**, so that hive loaded dirty. Values from that session may be stale. Holding **Shift** while loading also skips replay on purpose; use it only as a workaround.

---

## 4. Regedit vs. Registry Explorer

| | Registry Editor (regedit) | Registry Explorer |
|---|---|---|
| Purpose | Edit the **running** system's registry | Examine **offline** hive files forensically |
| File → Import | Merges a `.reg` file **into the live registry**. Not what you want for evidence. | n/a |
| Open dialog filter | `Registration Files (*.reg)` | Shows hive files |
| Plugins | None | Parses artifacts (Users, RecentDocs, UserAssist, USBSTOR…) into tables |

- **Gotcha:** hive files have **no file extension**, so a `*.reg` filter hides them ("No items match your search"). In any dialog, set the filter to **All Files (\*.\*)**.

---

## 5. SAM, RIDs and hexadecimal

### RIDs
- 📘 Lab (IS 3033 Lab 4 notes): the RID is the last number of a SID. Fixed RIDs: **500** Administrator, **501** Guest, **503** DefaultAccount, **504** WDAGUtilityAccount. New accounts start at **1000**.
- 📘 Lab (TryHackMe hint): accounts with RIDs starting with 10xx are user-created.
- 🔎 Beyond: in the SAM hive, each account's RID is the **name of its key** under `SAM\Domains\Account\Users`, written as 8-digit hex. The `Names` subkeys hold the usernames. Each one's (default) value has a **type number equal to the RID**, which is how Windows links name → RID.

### Converting hex to decimal
- Decimal positions are worth 1, 10, 100… Hex positions are worth **1, 16, 256…**
- Hex digits: 0–9, then **A=10, B=11, C=12, D=13, E=14, F=15**.
- Drop leading zeros (`000003E9` → `3E9`), multiply each digit by its position's worth, then add.

| Key name | Math | RID | Type |
|---|---|---|---|
| 000001F4 | 1×256 + 15×16 + 4 | 500 | Built-in |
| 000001F5 | 256 + 240 + 5 | 501 | Built-in |
| 000001F7 | 256 + 240 + 7 | 503 | Built-in |
| 000001F8 | 256 + 240 + 8 | 504 | Built-in |
| 000003E9 | 3×256 + 14×16 + 9 | 1001 | User-created |
| 000003EA | 768 + 224 + 10 | 1002 | User-created |
| 000003EB | 768 + 224 + 11 | 1003 | User-created |

- **Shortcut:** 1000 = `3E8` in hex. Keys starting `1F…` are in the 500s; keys of `3E8` or higher are user-created.
- Windows Calculator → Programmer mode → HEX → type the value → read DEC.
- 🔎 Beyond: computers use hex because **one hex digit = exactly 4 binary digits** (F = 1111). You'll see hex in hex viewers, MAC addresses and memory addresses.
- **Shortcut view:** click the `Users` key itself to get the plugin table (User Id in decimal, last login, login count, password hint).

---

## 6. Decoding text: UTF-16LE and ASCII

- The `UserPasswordHint` value is `RegBinary`: text stored as raw bytes, shown in hex.
- 🔎 Beyond: Windows stores most text as **UTF-16LE**. Every character takes **2 bytes**, and for plain English the second byte is `00`. **LE = little-endian**: the low byte comes first, so each letter appears *before* its `00`.
- Steps:
  1. Pair up the bytes and drop the `00`s.
  2. Look up each remaining byte in the ASCII table. Lowercase letters run from hex **61 (a) to 7A (z)**. Example: `63` = 6×16 + 3 = 99 = **c**.
- Tools that do it for you: Registry Explorer's Type viewer, the Users plugin's Password Hint column, CyberChef (*From Hex* → *Decode text: UTF-16LE*).

---

## 7. RecentDocs (files the user opened)

- Location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`, with one subkey per extension (`.txt`, `.pdf`, …).
- Records files opened through File Explorer. **MRUListEx** stores the order, most recent first.
- 🔎 Beyond: **only keys have timestamps, not values.** Each key has a **LastWrite** time, which updates when the list changes (a file is opened and moves to the top). So the key's LastWrite time equals the open time of the **MRU position 0** item only. Registry Explorer shows an "Opened On" time just for that top item.
- If the file you want isn't at position 0 in its extension subkey, check the root `RecentDocs` key, which mixes all extensions.
- Answer format: `YYYY-MM-DD HH:MM:SS` in **UTC**. Drop the `+00:00` and fractional seconds.

---

## 8. UserAssist (programs the user launched)

- Location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

| GUID | Records |
|---|---|
| `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` | Executables run directly |
| `{F4E57C4B-2036-45F0-A9AB-650BAE0CCEC4}` | Programs started from shortcuts (.lnk) |

- Stores the full path, run count, focus count and last-executed time for programs launched through the GUI.
- 🔎 Beyond: the value names are **ROT13**-encoded. Each letter is shifted 13 places (a↔n), and digits and symbols are unchanged: `pnyp.rkr` = `calc.exe`. Didier Stevens documented this in **2006**. It has been used since Windows 2000 and is still used in Windows 7 and later. It's obfuscation, not security.
- Registry Explorer decodes it; you can filter the Program Name column (for example `python`).
- From my debrief: a **keyword search** (Find box / Search) for `python` quickly surfaced the installer entries across the large hive.
- **Clue in this lab:** watch the **drive letter** of the path. The scenario mentions a network drive.

---

## 9. USB device forensics

### Where the data lives
- Devices attach to the **computer**, so the records are in **machine-wide** hives, not NTUSER.DAT.
- 🔎 Beyond: NTUSER.DAT's `MountPoints2` key can tie a volume to a specific **user**.

### Step 1: SOFTWARE, find the device by friendly name
- `Microsoft\Windows Portable Devices\Devices\<device>` → value `FriendlyName`.
- 🔎 Beyond: newer Windows 10 builds name these keys after the **volume**, not the hardware:

| Part of `SWD#WPDBUSENUM#{E251…}#0000000000100000` | Meaning |
|---|---|
| `SWD#WPDBUSENUM` | Software device on the Windows Portable Devices bus |
| `{…}` | **Volume GUID** (carry this forward) |
| `#0000000000100000` | Volume start offset: hex 100000 = 1,048,576 bytes = 1 MB. **Not a serial number.** |

- Older Windows versions put vendor, product and serial in this key name instead.

### Step 2: SYSTEM, match it to hardware
- **`MountedDevices`** (root of SYSTEM): the value `\??\Volume{GUID}` holds UTF-16LE text like `_??_USBSTOR#Disk&Ven_…&Prod_…#<serial>&0#{…}`.
- In this lab, Registry Explorer's USBSTOR plugin also showed a **Disk Id** column with the volume GUID, so I matched it directly. Hex is **not case-sensitive** (`E251921F` = `e251921f`).
- Cross-check: both devices in SOFTWARE matched both Disk Ids in USBSTOR.

### `Control\usbstor` vs. `Enum\USBSTOR`

| Key | Contains |
|---|---|
| `ControlSet001\Control\usbstor` | **Driver quirk settings** (`DeviceHackFlags`) for known-buggy models, keyed by vendor+product ID (`054C` = Sony). Ships with Windows, timestamps = image build date. **Not evidence.** |
| `ControlSet001\Enum\USBSTOR` | **Device history.** "Enum" = enumeration, the process where Windows detects and registers a device. Only devices actually connected appear here. |

- Structure: `Enum\USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\<serial>&0\`
- 🔎 Beyond: if the second character of the serial is `&`, the device had no unique serial and Windows generated one.

### Timestamps
`<serial>\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\`

| Subkey | Meaning |
|---|---|
| 0064 | First connected (driver install) |
| 0066 | **Last connected** |
| 0067 | Last removed |

- Stored as 64-bit **FILETIME** values (100-nanosecond intervals since Jan 1, 1601 UTC); Registry Explorer converts them.
- **Open question:** Last Removed was blank for both devices. Why might Windows have no removal time recorded?

### ControlSet001 vs. CurrentControlSet
- `CurrentControlSet` exists only on a **running** system; it points to one of the numbered sets.
- Offline, use `ControlSet001` and confirm with `SYSTEM\Select\Current` (1 = ControlSet001).

---

## 10. "Root nk record not found"

- 🔎 Beyond: a hive file starts with a **header** (the base block) that gives the offset of the **root key**. Keys are stored as **nk** ("named key") records. The error means the tool read the header but found no root key at that offset, so the file isn't a complete, valid hive.
- Common causes:
  - Selecting a `.LOG1` / `.LOG2`, `.sav` or RegBack file instead of the primary hive
  - Picking the VM's live, locked hive
  - A bad saved "clean" copy (replay done with mismatched or missing logs)
- Checks:
  - Use View → Details: real SYSTEM and SOFTWARE hives are **megabytes** in size.
  - Confirm the path is the triage folder.
  - Redo the replay with **both** of the hive's own logs.

---

## 11. Next: BAM/DAM and Amcache (from my debrief)

- 🔎 Beyond:
  - **BAM / DAM** (Background / Desktop Activity Moderator): `SYSTEM\ControlSet001\Services\bam\State\UserSettings\{SID}` (and `dam\...`). Records executable paths with a last-execution time **per user SID**.
  - **Amcache** (`C:\Windows\AppCompat\Programs\Amcache.hve`): file metadata, including **SHA-1 hashes**, under `Root\File\{Volume GUID}\`.
  - Correlating them: BAM shows **who** ran a program and **when**, and Amcache adds **what the file was** (a hash you can check against threat intel). UserAssist, Prefetch and ShimCache can corroborate.
- Practice goal: pull an execution path from BAM, then find the same binary in Amcache to get its hash and install context.

---

## 12. Gotchas

- Autopsy can't read live, locked hives. Use the **triage** copy.
- regedit → File → Import is the wrong dialog. It's for merging `.reg` files into the live registry.
- A `*.reg` file filter hides hive files. Switch to All Files.
- NTUSER.DAT and its logs are **hidden**. Type the filename.
- At the dirty prompt, select **both** LOG1 and LOG2 for the **same** hive.
- Don't cancel the save-clean-hive dialog unless you mean to analyze dirty.
- RIDs are **hex key names**; convert them before comparing to 1000.
- `Control\usbstor` ≠ `Enum\USBSTOR`.
- The WPD key's trailing `#0000000000100000` is a volume offset, not a serial.
- Offline hives have no `CurrentControlSet`. Use `ControlSet001`.
- TryHackMe timestamps: `YYYY-MM-DD HH:MM:SS`, UTC, no `+00:00`.

---

## Sources

**Lab material**
- [Windows Forensics 1, TryHackMe](https://tryhackme.com/room/windowsforensics1)
- IS 3033 Lab 4 notes (SIDs and RIDs), in this project

**Microsoft**
- [Registry Hives, Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [Well-known SIDs, Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
- [Local Accounts, Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)
- [Identifiers generated by Usbstor.sys, Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-generated-by-usbstor-sys)

**Research and practitioner references**
- [Digging Up the Past: Windows Registry Forensics Revisited (transaction logs), Google Cloud / Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited)
- [The Windows Registry Adventure #5: The regf file format, Google Project Zero (Dec 2024)](https://projectzero.google/2024/12/the-windows-registry-adventure-5-regf.html)
- [Investigating Windows Registry, ElcomSoft (Feb 2026)](https://blog.elcomsoft.com/2026/02/investigating-windows-registry/)
- [Windows NT Registry File (REGF) format, libyal/libregf](https://github.com/libyal/libregf)
- [Registry Transaction Logs, pt II, Harlan Carvey (Apr 2019)](https://windowsir.blogspot.com/2019/04/registry-transaction-logs-pt-ii.html)
- [ROT13 is used in Windows? You're joking!, Didier Stevens (Jul 2006)](https://blog.didierstevens.com/2006/07/24/rot13-is-used-in-windows-you%E2%80%99re-joking/)
- [Quickpost: Vigenère Is Beta-Only, Didier Stevens (Jan 2009)](https://blog.didierstevens.com/2009/01/29/quickpost-vigenere-is-beta-only/)
- [Investigating User File and Folder Activity with RecentDocs, Digital Investigator (Jun 2026)](https://digitalinvestigator.blogspot.com/2026/06/investigating-user-file-and-folder.html)
- [Windows USB Artifacts Forensics, Digital Investigator (Apr 2025)](https://digitalinvestigator.blogspot.com/2025/04/windows-usb-artifacts-forensics.html)
- [Evidence of Execution: BAM/DAM Forensics, Digital Investigator (Jun 2026)](https://digitalinvestigator.blogspot.com/2026/06/evidence-of-execution-bamdam-forensics.html)
- [Eric Zimmerman's tools](https://ericzimmerman.github.io/)
