# ONYX MOD ANALYZER

Windows PowerShell 5.1+ Minecraft mod integrity and threat analyzer. Scans a mods folder, verifies files against Modrinth,
inspects the real bytecode for cheat modules, droppers, agents and disguised binaries, then shows a colour terminal
summary and a full offline HTML report.

## Install and run (one command)

Open **CMD** or **PowerShell** and paste:

    powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/YOUR-USERNAME/Onyx-Mod-Analyzer/main/OnyxModAnalyzer.ps1')))"

Nothing is installed permanently. The script runs in memory, downloads its report template once, and stores reports in
`%APPDATA%\OnyxModAnalyzer\Reports`.

Pass options by adding them after the closing brackets, for example `-Depth Deep -Recurse -Compact`:

    powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/YOUR-USERNAME/Onyx-Mod-Analyzer/main/OnyxModAnalyzer.ps1'))) -Depth Deep -Recurse"

Safety tip: pin the URL to a release tag (replace `main` with `v2.1.0`) so the code you run can never change underneath you.
Read the script before you run any one-line installer, including this one.

## Run from a download

Download the repository ZIP, extract it, then double-click `Start-Onyx.bat` (or drag a mods folder onto it), or:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\OnyxModAnalyzer.ps1 -Path "D:\mods" -Depth Deep -Recurse

## Options

| Option | Meaning |
|---|---|
| `-Path <folder>` | Mods folder to scan. Launcher folders and a running game are auto-detected when omitted. |
| `-Depth Quick\|Standard\|Deep` | Scan depth. Deep adds entropy checks and extra structure checks. |
| `-Recurse` | Include sub-folders. |
| `-Compact` | Hide VERIFIED mods in the terminal list (they are still in the report). |
| `-Ascii` | Plain ASCII look for consoles that cannot draw box characters (or set env var `ONYX_ASCII=1`). |
| `-Offline` | Skip Modrinth and template download. |
| `-NoCache` | Do not use the local Modrinth cache. |
| `-NoPrompt` | No menus; exit code 0/1/2/3 = clean/review/suspicious/critical. |
| `-OpenReport` | Open the HTML report when finished. |
| `-OutDir <folder>` | Where to save reports. |
| `-MaxEntryMB <n>` | Largest archive entry to read (default 24). |

## What is new in v2.1.0

- **HTML report fixed.** The report could come out blank when the JSON export failed silently. The data is now built with
  error handling and a piece-by-piece fallback, embedded as Base64 so no character in a mod can break the page, and the
  report shows a visible error message instead of an empty page if anything still goes wrong.
- **New terminal look.** Banner, score panel, status bars, tree-style findings, inline progress bar. Adapts to window width.
- **One-line install.** Works straight from GitHub with no extra files (the template is fetched and cached).

## Interpretation

VERIFIED = SHA-1 matches a Modrinth release. UNKNOWN = not in the database and nothing found (private, CurseForge and
GitHub mods look like this). Findings are indicators for a human decision, not proof; legitimate mods can trip
individual rules.

## Configuration

`onyx.config.json` (next to the script, or in `%APPDATA%\OnyxModAnalyzer` for the one-line install) supports
`trustedDomains`, `allowlistSha1`, `ignoreTerms` and `extraTerms` (custom rules).

## What's new in 2.2.0

- **Fullwidth Unicode detection.** Labels such as the fullwidth spelling of "AutoCrystal" are converted to plain ASCII and matched against every cheat rule, so hidden labels resolve to the real module name.
- **More obfuscation checks:** numeric class names, Japanese kana class names, fullwidth class names, vowel-less gibberish names, single-character package paths.
- **Second hash database (Megabase)** as a fallback for files Modrinth does not know. Disable with `-NoMegabase`. A Megabase match is reported as `VerifiedBy = Megabase`.
- **Hollow-shell and unversioned nested-JAR detection.**
- **More cheat rules:** AxeSpam, AnchorTweaks, AirAnchor, LegitTotem, StunSlam, NoBounce, Antiknockback, KeyPearl, AutoWeb, jnativehook/imgui hook libraries, auth-bypass markers, and the packages and domains of several known cheat clients.
- **Known client names** (Asteria, Prestige, Xenon, Hellion, Argon, Virgin, ...) matched as whole words only, so "Argon2" and similar legitimate strings do not trigger.
- **Download origin:** AnyDesk and known cheat-client sites are flagged high.
