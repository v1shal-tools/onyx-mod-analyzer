<div align="center">

<pre>
   ___  _   _ __   __ __  __
  / _ \| \ | |\ \ / / \ \/ /
 | | | |  \| | \ V /   \  /
 | |_| | |\  |  | |    /  \
  \___/|_| \_|  |_|   /_/\_\
</pre>

# Onyx Mod Analyzer

**Find cheat clients, stealers and tampered JARs in your Minecraft mods folder in seconds.**

![Version](https://img.shields.io/badge/version-2.2.0-4cc9f0?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![No install](https://img.shields.io/badge/install-one%20command-3ddc97?style=for-the-badge)

[Quick start](#-quick-start) · [What it checks](#-what-it-checks) · [Results](#-reading-the-results) · [Options](#-options) · [FAQ](#-faq)

</div>

---

## Quick start

Open **Command Prompt** or **PowerShell** and paste:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/v1shal-tools/onyx-mod-analyzer/main/OnyxModAnalyzer.ps1')))"
```

Press **Enter** to scan the default folder, pick a detected launcher folder by number, or paste your own path. Nothing is installed: the script runs in memory and saves reports to `%APPDATA%\OnyxModAnalyzer\Reports`.

<details>
<summary><b>Scan a specific folder or use options</b></summary>

Add options after the closing `)))`:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/v1shal-tools/onyx-mod-analyzer/main/OnyxModAnalyzer.ps1'))) -Path 'D:\mods' -Depth Deep -Recurse"
```

</details>

<details>
<summary><b>Run from a download instead</b></summary>

Click **Code → Download ZIP**, extract it, then double-click `Start-Onyx.bat` (or drag a mods folder onto it). Or from a terminal:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\OnyxModAnalyzer.ps1 -Path "D:\mods" -Depth Deep -Recurse
```

</details>

> **Tip:** read any script before running a one-line installer, this one included. For extra safety, pin the URL to a release tag by replacing `main` with a tag such as `v2.2.0`.

---

## Highlights

| | |
|---|---|
| **Real bytecode scanning** | Reads class-file constants, not just file names, so renamed and obfuscated cheats are still caught |
| **Hash verification** | SHA-1 checked against Modrinth in one batched request, with Megabase as a fallback |
| **Hidden-label detection** | Fullwidth Unicode text (like `ＡｕｔｏＣｒｙｓｔａｌ`) is converted to plain text and matched |
| **Live game inspection** | Checks the running Minecraft JVM for agents and injection flags |
| **Offline HTML report** | Sortable, searchable report with per-file evidence, CSV/JSON export and a dark/light theme |
| **Private by design** | Only file hashes leave your PC. Reports never upload anywhere |

---

## What it checks

<details open>
<summary><b>Mod content</b></summary>

- Cheat module names: combat, movement, render, exploit and anti-cheat bypass
- Known hacked-client packages, domains and names (whole-word matching, so `Argon2` does not trigger)
- Process execution, dynamic class loading, Java agent manifests, input hooks, synthetic mouse input
- Discord webhooks, Telegram bot API, paste and file hosts, tunnels, hard-coded IPs, cheat-client domains
- Credential-theft indicators and behaviour combinations such as process launch plus download tools

</details>

<details open>
<summary><b>Disguise and tampering</b></summary>

- Class files hidden under other extensions, scrambled classes, embedded EXE/DLL files, hidden ZIPs
- Path traversal, duplicate entries, zip bombs, hidden NTFS data streams, high-entropy payloads (Deep)
- Hollow-shell mods and unversioned nested JARs
- Jars that impersonate known mods or reuse the id of a verified mod

</details>

<details open>
<summary><b>Obfuscation</b></summary>

- Short, numeric, look-alike, vowel-less, fullwidth and Japanese-kana class names
- Single-character package paths and known obfuscator signatures

</details>

<details open>
<summary><b>Your system</b></summary>

- **Download origin** from Windows Zone.Identifier (Discord, MediaFire, MEGA, Dropbox, Google Drive, AnyDesk, known cheat sites)
- **Running game:** `-javaagent`, `-agentlib`, `-agentpath`, bootclasspath, `-noverify`, class-loader overrides, DLLs loaded from temp folders
- **Timeline:** jars modified after the game launched, and mods loaded last session but missing now
- **Folder:** executables, scripts and renamed archives sitting next to your mods

</details>

---

## Reading the results

| Status | Meaning |
|---|---|
| ✅ **VERIFIED** | SHA-1 matches a Modrinth (or Megabase) release |
| ❔ **UNKNOWN** | Not in any database and nothing suspicious found. Private, CurseForge and GitHub mods look like this |
| 🟣 **OBFUSCATED** | Only obfuscation traits found |
| 🟡 **REVIEW** | A few indicators worth a quick look |
| 🟠 **SUSPICIOUS** | Several indicators, check manually |
| 🔴 **CRITICAL** | Strong indicators: cheat modules, webhooks, droppers or disguised binaries |

You also get an overall **security score out of 100** with a letter grade. Findings are indicators for a human decision, not proof. Legitimate mods can trip individual rules.

---

## Options

| Option | Description |
|---|---|
| `-Path <folder>` | Mods folder to scan. Launcher folders and a running game are auto-detected when omitted |
| `-Depth Quick\|Standard\|Deep` | Scan depth. Deep adds entropy checks and deeper nested-jar scanning |
| `-Recurse` | Include subfolders |
| `-Compact` | Hide VERIFIED mods in the terminal list (they stay in the report) |
| `-Ascii` | Plain ASCII look for consoles that can't draw box characters (or set `ONYX_ASCII=1`) |
| `-Offline` | No network lookups |
| `-NoMegabase` | Skip the Megabase fallback |
| `-NoCache` | Ignore the local Modrinth cache |
| `-NoPrompt` | No menus. Exit code `0/1/2/3` = clean / review / suspicious / critical |
| `-OpenReport` | Open the HTML report when finished |
| `-OutDir <folder>` | Where reports are saved |
| `-MaxEntryMB <n>` | Largest archive entry to read (default 24) |

### Custom rules

Create or edit `onyx.config.json` (next to the script, or in `%APPDATA%\OnyxModAnalyzer`) to add `trustedDomains`, `allowlistSha1`, `ignoreTerms` or your own `extraTerms`.

```json
{
  "trustedDomains": ["mymodsite.example"],
  "allowlistSha1": [],
  "ignoreTerms": [],
  "extraTerms": [{ "term": "ExampleCheatName", "category": "Custom rule", "severity": "high" }]
}
```

---

## FAQ

<details>
<summary><b>A mod I trust is flagged. Is it a cheat?</b></summary>

Not necessarily. Each finding shows exactly what matched and where, so you can judge it. Add the file's SHA-1 to `allowlistSha1`, or add a rule name to `ignoreTerms`, to silence it.

</details>

<details>
<summary><b>Why is my mod UNKNOWN?</b></summary>

It isn't in the Modrinth or Megabase database. That is normal for CurseForge-only, GitHub and private mods. UNKNOWN with no findings is not a warning.

</details>

<details>
<summary><b>What data leaves my PC?</b></summary>

Only SHA-1 hashes, sent to Modrinth and Megabase for verification. No files, file names or paths are uploaded. Use `-Offline` to send nothing.

</details>

<details>
<summary><b>The report is blank or plain.</b></summary>

The report template is downloaded from this repository the first time. If you are offline or GitHub is unreachable, you get a plain data page instead. Run once with a connection, or use the downloaded ZIP version.

</details>

<details>
<summary><b>The box characters look broken.</b></summary>

Run with `-Ascii`, or use Windows Terminal.

</details>

---

## Requirements

Windows 10 or 11 with PowerShell 5.1 or newer (built in).

## Disclaimer

Onyx is a heuristic tool. A clean result does not guarantee a mod is safe, and a flag does not prove cheating. Review flagged files yourself before taking action against anyone.

<div align="center">

Made for fair play in Minecraft.

</div>
