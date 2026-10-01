#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Path,
    [ValidateSet('Quick','Standard','Deep')][string]$Depth = 'Standard',
    [switch]$Offline,
    [switch]$Recurse,
    [switch]$NoCache,
    [switch]$NoMegabase,
    [switch]$NoPrompt,
    [switch]$OpenReport,
    [switch]$Compact,
    [switch]$Ascii,
    [string]$OutDir,
    [int]$MaxEntryMB = 24
)

$ErrorActionPreference = 'SilentlyContinue'
$Version = '2.2.0'

$RepoRaw = if ($env:ONYX_REPO_RAW) { $env:ONYX_REPO_RAW.TrimEnd('/') } else { 'https://raw.githubusercontent.com/v1shal-tools/Onyx-Mod-Analyzer/main' }
if ($env:ONYX_ASCII) { $Ascii = [switch]$true }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$AppDir = Join-Path $env:APPDATA 'OnyxModAnalyzer'
$ReportDir = if ($OutDir) { $OutDir } else { Join-Path $AppDir 'Reports' }
$CachePath = Join-Path $AppDir 'modrinth-cache.json'
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

# ---------------------------------------------------------------- config
$Cfg = @{ TrustedDomains = @(); AllowSha1 = @(); IgnoreTerms = @(); ExtraTerms = @() }
$cfgFile = $null
foreach ($d in @($PSScriptRoot, $AppDir)) {
    if ($d -and -not $cfgFile) { $t = Join-Path $d 'onyx.config.json'; if (Test-Path -LiteralPath $t) { $cfgFile = $t } }
}
if ($cfgFile) {
    try {
        $c = Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
        if ($c.trustedDomains) { $Cfg.TrustedDomains = @($c.trustedDomains) }
        if ($c.allowlistSha1)  { $Cfg.AllowSha1 = @($c.allowlistSha1 | ForEach-Object { ([string]$_).ToLower() }) }
        if ($c.ignoreTerms)    { $Cfg.IgnoreTerms = @($c.ignoreTerms | ForEach-Object { ([string]$_).ToLower() }) }
        if ($c.extraTerms)     { $Cfg.ExtraTerms = @($c.extraTerms) }
    } catch { Write-Host '  [warn] onyx.config.json could not be parsed; using defaults.' -ForegroundColor Yellow }
}

# ---------------------------------------------------------------- native helper (fast constant-pool + entropy)
$Native = $false
try {
Add-Type -TypeDefinition @"
using System;
using System.Text;
public static class OnyxNative {
  public static double Entropy(byte[] d, int max) {
    int n = d.Length < max ? d.Length : max;
    if (n == 0) return 0.0;
    int[] c = new int[256];
    for (int i = 0; i < n; i++) c[d[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) { if (c[i] == 0) continue; double p = (double)c[i] / n; e -= p * Math.Log(p, 2.0); }
    return e;
  }
  public static string ConstantPool(byte[] d) {
    if (d == null || d.Length < 10 || d[0] != 0xCA || d[1] != 0xFE || d[2] != 0xBA || d[3] != 0xBE) return null;
    int count = (d[8] << 8) | d[9];
    int p = 10;
    StringBuilder sb = new StringBuilder();
    for (int i = 1; i < count; i++) {
      if (p >= d.Length) break;
      int tag = d[p++];
      switch (tag) {
        case 1: {
          if (p + 2 > d.Length) return sb.ToString();
          int len = (d[p] << 8) | d[p + 1]; p += 2;
          if (p + len > d.Length) return sb.ToString();
          sb.Append(Encoding.UTF8.GetString(d, p, len)); sb.Append('\n'); p += len; break; }
        case 3: case 4: p += 4; break;
        case 5: case 6: p += 8; i++; break;
        case 7: case 8: case 16: case 19: case 20: p += 2; break;
        case 9: case 10: case 11: case 12: case 17: case 18: p += 4; break;
        case 15: p += 3; break;
        default: return sb.ToString();
      }
    }
    return sb.ToString();
  }
}
"@
    $Native = $true
} catch {}

$SevW = @{ critical = 40; high = 20; medium = 8; low = 3; info = 0 }
$RuleList = New-Object System.Collections.Generic.List[object]

function Add-Rule {
    param([string]$Term, [string]$Cat, [string]$Sev, [string]$Note, [string]$Kind = 'term', [bool]$Hidden = $false)
    if ($Cfg.IgnoreTerms -contains $Term.ToLower()) { return }
    $RuleList.Add([pscustomobject]@{
        Id = ($Kind.Substring(0,1) + ':' + $Term.ToLower()); Term = $Term; Cat = $Cat
        Sev = $Sev; Note = $Note; Kind = $Kind; Hidden = $Hidden })
}
function Add-Terms {
    param([string[]]$Terms, [string]$Cat, [string]$Sev, [string]$Note, [string]$Kind = 'term')
    foreach ($t in $Terms) { Add-Rule -Term $t -Cat $Cat -Sev $Sev -Note $Note -Kind $Kind }
}

Add-Terms @('KillAura','AimAssist','AutoCrystal','AutoHitCrystal','CrystalAura','TriggerBot','SilentAim','BowAimbot','ShieldBreaker','ShieldDisabler','AutoAnchor','DoubleAnchor','SafeAnchor','AutoBed','BedAura','AutoDoubleHand','PopSwitch','MaceSwap','AutoBreach','AutoCrit','ReachHack','AutoPot','AutoTotem','HoverTotem','InventoryTotem') 'Combat cheat module' 'high' 'Module name typical of PvP cheats'
Add-Terms @('Criticals','AutoClicker','WTap','JumpReset','SprintReset','AutoGap','AutoPearl','AutoTPA','AutoArmor','ChestSteal','AutoMine','AutoFirework','ElytraSwap','FastXP','AutoBridge','PacketMine') 'Combat / utility cheat module' 'medium' 'Module name common in cheat clients (also appears in some legit QoL mods)'
Add-Terms @('FlyHack','SpeedHack','PacketFly') 'Movement cheat module' 'high' 'Movement cheat module name'
Add-Terms @('BHop','AntiFall','NoKnockback','AntiKB','StepHack','WaterWalk','NoSlow','NoJumpDelay','ElytraSpeed') 'Movement cheat module' 'medium' 'Movement module name common in cheat clients'
Add-Terms @('BlockESP','PlayerESP','XRayHack') 'Render cheat module' 'high' 'ESP / X-ray cheat module name'
Add-Terms @('Tracers','NewChunks','FakeItem') 'Render cheat module' 'medium' 'Render cheat module name'
Add-Terms @('FakeLag','PingSpoof','FakeInv','FakeNick','PackSpoof') 'Exploit / spoof module' 'medium' 'Spoofing / exploit module name'
Add-Terms @('Freecam','FastPlace','AutoEat') 'Utility module' 'low' 'Utility module name (often legitimate)'
Add-Terms @('GrimBypass','VulcanBypass','MatrixBypass','AACBypass','VerusDisabler','WatchdogBypass','NCPBypass') 'Anti-cheat bypass' 'high' 'Names an anti-cheat it bypasses'
Add-Terms @('meteordevelopment','meteorclient','wurstclient','ccbluex','liquidbounce','rusherhack','thunderhack','bleachhack','kamiblue','zeroeightsix','aristois','impactclient','salhack','futureclient','novoline','sigmaclient') 'Known hacked-client signature' 'high' 'Package or name of a known hacked client'
Add-Terms @('SessionStealer','TokenLogger','TokenGrabber','KeyLogger','ReverseShell') 'Stealer / RAT' 'critical' 'Name typical of stealers and remote shells'
Add-Terms @('RemoteAccess','Backdoor') 'Stealer / RAT' 'high' 'Name typical of remote-access code'
Add-Terms @('cheat-refmap.json') 'Cheat client marker' 'high' 'Mixin refmap named after a cheat client'
Add-Terms @('phantom-refmap.json','LicenseCheckMixin') 'Cheat client marker' 'medium' 'Marker seen in hacked-client jars'
Add-Terms @('client-refmap.json','ClientPlayerInteractionManagerAccessor') 'Cheat client marker' 'low' 'Weak marker, common in legit mods too'
Add-Terms @('powershell','EncodedCommand','Invoke-WebRequest','DownloadFile','DownloadString','certutil','bitsadmin','mshta','wscript','regsvr32','rundll32','schtasks','CurrentVersion\Run') 'System tool / downloader' 'high' 'Windows scripting or download tooling referenced from mod code'
Add-Terms @('cmd.exe') 'System tool / downloader' 'medium' 'Command interpreter referenced from mod code'
Add-Terms @('discordcanary','discordptb','launcher_accounts','Login Data','cookies.sqlite','logins.json','os_crypt','api.telegram.org') 'Credential theft' 'high' 'Path or endpoint used by credential stealers'
Add-Terms @('SetWindowsHookEx') 'Input hooking' 'high' 'Global keyboard/mouse hook API'
Add-Terms @('GetAsyncKeyState') 'Input hooking' 'medium' 'Polls global key state (keybind libs use it too)'
Add-Rule -Term 'leveldb' -Cat 'Credential theft' -Sev 'info' -Note 'helper' -Hidden $true
foreach ($x in $Cfg.ExtraTerms) {
    if ($x.term) {
        $sv = 'medium'; if ($x.severity -and $SevW.ContainsKey(([string]$x.severity).ToLower())) { $sv = ([string]$x.severity).ToLower() }
        $ct = 'Custom rule'; if ($x.category) { $ct = [string]$x.category }
        Add-Rule -Term ([string]$x.term) -Cat $ct -Sev $sv -Note 'Matched a rule from onyx.config.json'
    }
}

Add-Rule -Term 'java/lang/ProcessBuilder' -Cat 'Process execution' -Sev 'medium' -Note 'Can launch external processes' -Kind 'exact'
Add-Rule -Term 'java/net/URLClassLoader' -Cat 'Dynamic code loading' -Sev 'medium' -Note 'Loads classes from URLs or paths at runtime' -Kind 'exact'
Add-Rule -Term 'java/lang/instrument/Instrumentation' -Cat 'Dynamic code loading' -Sev 'high' -Note 'Java agent / instrumentation API' -Kind 'exact'
Add-Rule -Term 'sun/misc/Unsafe' -Cat 'Dynamic code loading' -Sev 'low' -Note 'Low-level memory API (some legit libraries use it)' -Kind 'exact'
Add-Rule -Term 'loadLibrary' -Cat 'Native code' -Sev 'low' -Note 'Loads native libraries' -Kind 'exact'
foreach ($h in @('java/lang/Runtime','exec','defineClass','java/awt/Robot','mousePress','javax/crypto/Cipher','java/util/Base64')) {
    Add-Rule -Term $h -Cat 'helper' -Sev 'info' -Note 'helper' -Kind 'exact' -Hidden $true
}


Add-Terms @('AxeSpam','AnchorTweaks','AirAnchor','LegitTotem','StunSlam','AutoNethPot','AutoDtap','AutoPotRefill','SpearSwap','WebMacro','AnchorAction','LagReach') 'Combat cheat module' 'high' 'Module name typical of PvP cheats'
Add-Terms @('NoBounce','Antiknockback','AutoWeb','KeyPearl','SelfDestruct','BaseFinder','StashFinder','TrailFinder','HideClient','LootYeeter') 'Combat / utility cheat module' 'medium' 'Module name common in cheat clients'
Add-Terms @('AuthBypass','obfuscatedAuth') 'Cheat client marker' 'high' 'Licence / auth bypass marker used by cheat clients'
Add-Terms @('jnativehook','imgui.binding','imgui.gl3','imgui.glfw') 'Input hooking' 'medium' 'Global input hook / overlay library used by macro clients'
Add-Terms @('org/chainlibs','org.chainlibs','skid/krypton','skid.krypton','dev/krypton','dev.krypton','xyz/greaj','xyz.greaj','dev/gambleclient','dev.gambleclient','com/alan/clients','club/maxstats','wtf/moonlight','today/opai') 'Known hacked-client signature' 'high' 'Package path of a known hacked client'
Add-Terms @('novaclient.lol','dqrkis.xyz','prestigeclient.vip','198macros.com','doomsdayclient.com','vape.gg','intent.store','riseclient.com') 'Known hacked-client signature' 'high' 'Domain of a known cheat client'
Add-Terms @('Asteria','Prestige','Xenon','Hellion','Argon','Virgin','Pandaware','Catlean','Gypsy') 'Known hacked-client name' 'medium' 'Bare name of a known cheat client (whole-word, case-sensitive; can collide with ordinary words)' 'word'
Add-Terms @('AsteriaClient','PrestigeClient','XenonClient','HellionClient','ArgonClient','VirginClient','DonutClient','GypsyClient','CatleanClient','AstolfoClient','Novoclient','IntentClient','VapeClient','VapeLite','DoomsdayClient','DqrkisClient','Dqrkis') 'Known hacked-client signature' 'high' 'Name of a known hacked client (whole-word, case-sensitive)' 'word'

$script:TermIndex = @{}; $script:ExactIndex = @{}
$alts = New-Object System.Collections.Generic.List[string]
foreach ($r in @($RuleList | Where-Object { $_.Kind -eq 'term' } | Sort-Object { $_.Term.Length } -Descending)) {
    $script:TermIndex[$r.Term.ToLower()] = $r
    [void]$alts.Add([regex]::Escape($r.Term))
}
$exAlts = New-Object System.Collections.Generic.List[string]
foreach ($r in @($RuleList | Where-Object { $_.Kind -eq 'exact' })) {
    $script:ExactIndex[$r.Term] = $r
    [void]$exAlts.Add([regex]::Escape($r.Term))
}
$script:WordIndex = @{}
$wAlts = New-Object System.Collections.Generic.List[string]
foreach ($r in @($RuleList | Where-Object { $_.Kind -eq 'word' } | Sort-Object { $_.Term.Length } -Descending)) {
    $script:WordIndex[$r.Term] = $r
    [void]$wAlts.Add([regex]::Escape($r.Term))
}
$RO = [System.Text.RegularExpressions.RegexOptions]
$TermRegex  = New-Object System.Text.RegularExpressions.Regex(($alts -join '|'), ($RO::IgnoreCase -bor $RO::Compiled))
$ExactRegex = New-Object System.Text.RegularExpressions.Regex(('^(?:' + ($exAlts -join '|') + ')$'), ($RO::Multiline -bor $RO::Compiled))
$ExactLoose = New-Object System.Text.RegularExpressions.Regex(('(?:' + ($exAlts -join '|') + ')'), $RO::Compiled)
$ObfRegex   = New-Object System.Text.RegularExpressions.Regex('\b(Skidfuscator|Paramorphism|Caesium|Bozar|Branchlock|Binscure|Qprotect|Allatori|ZKM|Zelix|JNIC|Scuti|Radon|Stringer|DashO|superblaubeere27|Obfuscated by)\b', $RO::Compiled)
$UrlRegex   = New-Object System.Text.RegularExpressions.Regex('https?://([A-Za-z0-9.\-]{3,253})(?::\d+)?(/[^\s"''<>\\]{0,120})?', $RO::Compiled)
$WordRegex  = New-Object System.Text.RegularExpressions.Regex(('(?<![A-Za-z0-9])(?:' + ($wAlts -join '|') + ')(?![A-Za-z0-9])'), $RO::Compiled)
$FwRegex    = New-Object System.Text.RegularExpressions.Regex('(?:[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19][\u3000 ]?){3,}', $RO::Compiled)
$HookRegex  = New-Object System.Text.RegularExpressions.Regex('discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', ($RO::IgnoreCase -bor $RO::Compiled))

$TrustedHostRegex = '(^|\.)(modrinth\.com|curseforge\.com|minecraft\.net|mojang\.com|fabricmc\.net|quiltmc\.org|neoforged\.net|minecraftforge\.net|spongepowered\.org|github\.com|gitlab\.com|apache\.org|w3\.org|java\.com|oracle\.com|sun\.com|google\.com|googleapis\.com|jetbrains\.com|kotlinlang\.org|maven\.org|sonatype\.org|gradle\.org|eclipse\.org|openjdk\.org|xml\.org|xmlpull\.org|ko-fi\.com|patreon\.com|paypal\.com|youtube\.com|discord\.gg|twitter\.com|x\.com|mozilla\.org|slf4j\.org|jitpack\.io|shedaniel\.me|terraformersmc\.com|tterrag\.com|minecraftservices\.com|example\.com|localhost|creativecommons\.org|opensource\.org|gnu\.org)$'
$PayloadHostRegex = '(^|\.)(pastebin\.com|hastebin\.com|paste\.ee|ghostbin\.\w+|rentry\.co|transfer\.sh|anonfiles\.com|gofile\.io|file\.io|catbox\.moe|0x0\.st|bashupload\.com|mediafire\.com|mega\.nz|dropbox\.com|drive\.google\.com|raw\.githubusercontent\.com|gist\.githubusercontent\.com)$'
$TunnelHostRegex  = '(^|\.)(ngrok\.io|ngrok-free\.app|serveo\.net|localhost\.run|trycloudflare\.com|duckdns\.org|no-ip\.\w+|hopto\.org|ddns\.net|playit\.gg)$'
$SkipPrefixes = @('org/spongepowered/','com/google/','kotlin/','kotlinx/','org/jetbrains/','org/apache/','org/objectweb/','io/netty/','javax/','net/fabricmc/loader/','org/slf4j/','org/lwjgl/','it/unimi/','com/electronwill/','org/yaml/','org/json/','org/joml/','org/intellij/','com/mojang/')
$TextExts = @('.json','.mf','.txt','.properties','.toml','.yml','.yaml','.cfg','.xml','.mcmeta','.info','.sf','.md','.conf','.lang','.ini','.json5','.sh','.bat','.cmd','.ps1','.vbs')
$ScriptExts = @('.bat','.cmd','.ps1','.vbs','.vbe','.lnk','.scr','.msi')
$NativeExts = @('.dll','.exe','.so','.dylib','.jnilib')


$script:Wd = 78
try { $ww = $Host.UI.RawUI.WindowSize.Width; if ($ww -gt 0) { $script:Wd = [Math]::Min(110, [Math]::Max(78, $ww - 1)) } } catch {}
$script:UI = -not $Ascii
if ($script:UI) { try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { $script:UI = $false } }
if ($script:UI) {
    $script:G = @{
        full = [string][char]0x2588; empty = [string][char]0x2591; hs = [string][char]0x2500; hd = [string][char]0x2550; vd = [string][char]0x2551
        tl = [string][char]0x2554; tr = [string][char]0x2557; bl = [string][char]0x255A; br = [string][char]0x255D
        dot = [string][char]0x25CF; ok = [string][char]0x221A; arr = [string][char]0x25BA; bul = [string][char]0x2022
        tee = ([string][char]0x251C + [string][char]0x2500); ell = ([string][char]0x2514 + [string][char]0x2500)
    }
} else {
    $script:G = @{ full = '#'; empty = '.'; hs = '-'; hd = '='; vd = '|'; tl = '+'; tr = '+'; bl = '+'; br = '+'; dot = '*'; ok = '+'; arr = '>'; bul = '-'; tee = '|-'; ell = '`-' }
}
$script:StCol = @{ VERIFIED = 'Green'; UNKNOWN = 'Yellow'; OBFUSCATED = 'Magenta'; REVIEW = 'DarkYellow'; SUSPICIOUS = 'Red'; CRITICAL = 'Red' }

function W { param([string]$T = '', [string]$C = 'Gray') Write-Host $T -ForegroundColor $C }
function WP {
    param([object[]]$Parts)
    if ($Parts.Count -ge 1 -and $Parts[0] -is [string]) { $Parts = , $Parts }
    foreach ($p in $Parts) { Write-Host ([string]$p[0]) -NoNewline -ForegroundColor ([string]$p[1]) }
    Write-Host ''
}
function Rep { param([string]$S, [int]$N) if ($N -le 0) { return '' } return ($S * $N) }
function Center { param([string]$S) return ((' ' * [Math]::Max(0, [int](($script:Wd - $S.Length) / 2))) + $S) }
function Rule {
    param([string]$Title = '')
    if ($Title) {
        $t = ' ' + $Title + ' '
        WP @( @('  ', 'Gray'), @((Rep $script:G.hs 2), 'DarkGray'), @($t, 'White'), @((Rep $script:G.hs ($script:Wd - 6 - $t.Length)), 'DarkGray') )
    } else { W ('  ' + (Rep $script:G.hs ($script:Wd - 4))) 'DarkGray' }
}
function Box-Top { W ('  ' + $script:G.tl + (Rep $script:G.hd ($script:Wd - 6)) + $script:G.tr) 'DarkGray' }
function Box-Bot { W ('  ' + $script:G.bl + (Rep $script:G.hd ($script:Wd - 6)) + $script:G.br) 'DarkGray' }
function Box-Row {
    param([object[]]$Parts)
    $len = 0; foreach ($p in $Parts) { $len += ([string]$p[0]).Length }
    $pad = [Math]::Max(0, ($script:Wd - 8) - $len)
    $first = , @(('  ' + $script:G.vd + ' '), 'DarkGray')
    $last = , @(((' ' * $pad) + ' ' + $script:G.vd), 'DarkGray')
    WP ($first + $Parts + $last)
}
function Bar {
    param([double]$Frac, [int]$Width)
    $f = [int][Math]::Round([Math]::Max(0, [Math]::Min(1, $Frac)) * $Width)
    return @((Rep $script:G.full $f), (Rep $script:G.empty ($Width - $f)))
}
function Wrap {
    param([string]$S, [int]$N)
    $out = @(); $line = ''
    foreach ($w in ($S -split '\s+')) {
        if ($line -and (($line.Length + $w.Length + 1) -gt $N)) { $out += $line; $line = $w }
        elseif ($line) { $line += ' ' + $w } else { $line = $w }
    }
    if ($line) { $out += $line }
    return $out
}
function Step { param([int]$N, [string]$T) WP @( @('  ', 'Gray'), @(($script:G.arr + ' '), 'Cyan'), @(('[{0}/6] ' -f $N), 'DarkGray'), @($T, 'White') ) }
function Show-Bar {
    param([string]$Label, [int]$I, [int]$N, [string]$Item)
    if ($NoPrompt) { return }
    $bw = 26
    $frac = 1.0; if ($N -gt 0) { $frac = $I / $N }
    $b = Bar $frac $bw
    $tail = ('  {0,3}%  {1}/{2}  {3}' -f [int]($frac * 100), $I, $N, (Cut $Item ($script:Wd - 52)))
    Write-Host "`r        " -NoNewline
    Write-Host $b[0] -NoNewline -ForegroundColor Cyan
    Write-Host $b[1] -NoNewline -ForegroundColor DarkGray
    Write-Host ($tail.PadRight([Math]::Max(1, $script:Wd - 8 - $bw))) -NoNewline -ForegroundColor Gray
}
function Clear-Bar { if ($NoPrompt) { return } Write-Host ("`r" + (' ' * ($script:Wd - 1)) + "`r") -NoNewline }

function Show-Banner {
    if (-not $NoPrompt) { Clear-Host }
    $font = @{
        O = @(' ### ', '#   #', '#   #', '#   #', ' ### ')
        N = @('#   #', '##  #', '# # #', '#  ##', '#   #')
        Y = @('#   #', ' # # ', '  #  ', '  #  ', '  #  ')
        X = @('#   #', ' # # ', '  #  ', ' # # ', '#   #')
    }
    $cols = @('White', 'Cyan', 'Cyan', 'DarkCyan', 'DarkCyan')
    $pad = ' ' * [Math]::Max(0, [int](($script:Wd - 49) / 2))
    W ''
    for ($r = 0; $r -lt 5; $r++) {
        $line = ''
        foreach ($ch in 'O', 'N', 'Y', 'X') { $line += ($font[$ch][$r].Replace(' ', '  ').Replace('#', ($script:G.full + $script:G.full))) + '   ' }
        W ($pad + $line) $cols[$r]
    }
    W ''
    W (Center 'M O D   S E C U R I T Y   A N A L Y Z E R') 'Cyan'
    W (Center ('v{0}  {1}  {2} scan  {1}  PowerShell {3}' -f $Version, $script:G.bul, $Depth, $PSVersionTable.PSVersion.Major)) 'DarkGray'
    W ''
    Rule
}
function Format-Size { param([double]$B) if ($B -ge 1MB) { return ('{0:N1} MB' -f ($B / 1MB)) } if ($B -ge 1KB) { return ('{0:N0} KB' -f ($B / 1KB)) } return ('{0} B' -f [int]$B) }
function Cut { param([string]$S, [int]$N) if ($S.Length -le $N) { return $S } return ($S.Substring(0, $N - 3) + '...') }
function Iso { param($D) if ($null -eq $D) { return $null } try { return ([datetime]$D).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return $null } }

# ---------------------------------------------------------------- hashing / zone / cache
function Get-Hashes {
    param([string]$P)
    $r = @{ Sha1 = ''; Sha256 = '' }
    $fs = $null
    try {
        $fs = New-Object IO.FileStream($P, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $a = [Security.Cryptography.SHA1]::Create(); $b = [Security.Cryptography.SHA256]::Create()
        $buf = New-Object byte[] 1048576
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            [void]$a.TransformBlock($buf, 0, $n, $null, 0); [void]$b.TransformBlock($buf, 0, $n, $null, 0)
        }
        [void]$a.TransformFinalBlock($buf, 0, 0); [void]$b.TransformFinalBlock($buf, 0, 0)
        $r.Sha1 = ([BitConverter]::ToString($a.Hash)).Replace('-', '').ToLower()
        $r.Sha256 = ([BitConverter]::ToString($b.Hash)).Replace('-', '').ToLower()
    } catch {} finally { if ($fs) { $fs.Dispose() } }
    return $r
}

function Get-ZoneInfo {
    param([string]$P)
    $z = @{ Present = $false; Name = 'Unknown (no mark-of-the-web)'; Url = ''; Referrer = ''; Flag = $false; Hot = $false }
    try {
        $raw = Get-Content -LiteralPath ($P + ':Zone.Identifier') -Raw -ErrorAction Stop
        $z.Present = $true; $z.Name = 'Downloaded (origin not recorded)'
        if ($raw -match 'HostUrl=(\S+)') { $z.Url = $Matches[1] }
        if ($raw -match 'ReferrerUrl=(\S+)') { $z.Referrer = $Matches[1] }
        $u = $z.Url; if (-not $u) { $u = $z.Referrer }
        $h = ''
        $uri = $null
        if ($u -and [uri]::TryCreate($u, [UriKind]::Absolute, [ref]$uri)) { $h = $uri.Host.ToLower() }
        if ($h) {
            if     ($h -match '(^|\.)modrinth\.com$')                        { $z.Name = 'Modrinth' }
            elseif ($h -match '(^|\.)(curseforge\.com|forgecdn\.net)$')      { $z.Name = 'CurseForge' }
            elseif ($h -match '(^|\.)(github\.com|githubusercontent\.com)$') { $z.Name = 'GitHub' }
            elseif ($h -match '(^|\.)(discord\.com|discordapp\.com|discordapp\.net)$') { $z.Name = 'Discord CDN'; $z.Flag = $true }
            elseif ($h -match '(^|\.)mediafire\.com$')                       { $z.Name = 'MediaFire'; $z.Flag = $true }
            elseif ($h -match '(^|\.)(mega\.nz|mega\.io)$')                  { $z.Name = 'MEGA'; $z.Flag = $true }
            elseif ($h -match '(^|\.)dropbox\.com$')                         { $z.Name = 'Dropbox'; $z.Flag = $true }
            elseif ($h -match '(^|\.)(drive\.google\.com|googleusercontent\.com)$') { $z.Name = 'Google Drive'; $z.Flag = $true }
            elseif ($h -match '(anonfiles|gofile|catbox|file\.io|transfer\.sh)') { $z.Name = "File host ($h)"; $z.Flag = $true }
            elseif ($h -match '(^|\.)anydesk\.com$') { $z.Name = 'AnyDesk'; $z.Hot = $true }
            elseif ($h -match '(^|\.)(doomsdayclient\.com|prestigeclient\.vip|198macros\.com|dqrkis\.xyz|novaclient\.lol)$') { $z.Name = "Cheat-client site ($h)"; $z.Hot = $true }
            else { $z.Name = $h }
        }
    } catch {}
    return $z
}

function Load-Cache {
    $c = @{}
    if ($NoCache -or -not (Test-Path -LiteralPath $CachePath)) { return $c }
    try {
        $j = Get-Content -LiteralPath $CachePath -Raw | ConvertFrom-Json
        foreach ($p in $j.PSObject.Properties) { $c[$p.Name] = $p.Value }
    } catch {}
    return $c
}
function Save-Cache { param($C) if ($NoCache) { return } try { ($C | ConvertTo-Json -Depth 6 -Compress) | Set-Content -LiteralPath $CachePath -Encoding UTF8 } catch {} }

function Resolve-Modrinth {
    param([string[]]$Hashes)
    $state = 'ok'; $out = @{}
    if ($Offline) { return @{ State = 'offline'; Map = $out } }
    $cache = Load-Cache
    $now = Get-Date
    $need = New-Object System.Collections.Generic.List[string]
    foreach ($h in $Hashes) {
        if (-not $h) { continue }
        $e = $cache[$h]
        $fresh = $false
        if ($e -and $e.ts) {
            $age = ($now - [datetime]$e.ts).TotalHours
            if ($e.found -and $age -lt 336) { $fresh = $true } elseif ((-not $e.found) -and $age -lt 6) { $fresh = $true }
        }
        if ($fresh) { if ($e.found) { $out[$h] = $e } } else { [void]$need.Add($h) }
    }
    $ua = "OnyxModAnalyzer/$Version (local defensive scanner)"
    $versions = @{}
    $failed = $false
    for ($i = 0; $i -lt $need.Count; $i += 100) {
        $last = [Math]::Min($i + 99, $need.Count - 1)
        $chunk = @($need[$i..$last])
        $body = (@{ hashes = $chunk; algorithm = 'sha1' } | ConvertTo-Json -Compress)
        try {
            $resp = Invoke-RestMethod -Uri 'https://api.modrinth.com/v2/version_files' -Method Post -ContentType 'application/json' -Body $body -UserAgent $ua -TimeoutSec 30 -ErrorAction Stop
            foreach ($p in $resp.PSObject.Properties) { $versions[$p.Name.ToLower()] = $p.Value }
            foreach ($h in $chunk) { if (-not $versions.ContainsKey($h)) { $cache[$h] = [pscustomobject]@{ found = $false; ts = $now.ToString('o') } } }
        } catch { $failed = $true }
    }
    $pids = @($versions.Values | ForEach-Object { $_.project_id } | Sort-Object -Unique)
    $projects = @{}
    for ($i = 0; $i -lt $pids.Count; $i += 50) {
        $last = [Math]::Min($i + 49, $pids.Count - 1)
        $ids = '[' + ((@($pids[$i..$last]) | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
        try {
            $pr = Invoke-RestMethod -Uri ('https://api.modrinth.com/v2/projects?ids=' + [uri]::EscapeDataString($ids)) -UserAgent $ua -TimeoutSec 30 -ErrorAction Stop
            foreach ($p in @($pr)) { $projects[$p.id] = $p }
        } catch {}
    }
    foreach ($h in $versions.Keys) {
        $v = $versions[$h]; $p = $projects[$v.project_id]
        $rec = [pscustomobject]@{
            found = $true; ts = $now.ToString('o'); project_id = $v.project_id; version_number = $v.version_number
            version_name = $v.name; loaders = @($v.loaders); game_versions = @($v.game_versions); published = $v.date_published
            title = $(if ($p) { $p.title } else { $null }); slug = $(if ($p) { $p.slug } else { $null })
            project_type = $(if ($p) { $p.project_type } else { $null }); downloads = $(if ($p) { $p.downloads } else { $null }); source = 'Modrinth'
        }
        $cache[$h] = $rec; $out[$h] = $rec
    }
    # Megabase fallback for hashes Modrinth does not know (second opinion, not a replacement)
    $megaHits = 0
    if (-not $NoMegabase) {
        $miss = @($need | Where-Object { -not $versions.ContainsKey($_) })
        $mfail = 0
        foreach ($h in $miss) {
            if ($mfail -ge 3) { break }
            try {
                $r = Invoke-RestMethod -Uri ('https://megabase.vercel.app/api/query?hash=' + $h) -UserAgent $ua -TimeoutSec 10 -ErrorAction Stop
                if ((-not $r.error) -and $r.data -and $r.data.name) {
                    $rec = [pscustomobject]@{
                        found = $true; ts = $now.ToString('o'); project_id = $null; version_number = [string]$r.data.version; version_name = $null
                        loaders = @(); game_versions = @(); published = $null; title = [string]$r.data.name; slug = $null
                        project_type = $null; downloads = $null; source = 'Megabase'
                    }
                    $cache[$h] = $rec; $out[$h] = $rec; $megaHits++
                }
            } catch {
                $code = 0
                try { $code = [int]$_.Exception.Response.StatusCode } catch {}
                if (-not ($code -ge 400 -and $code -lt 500)) { $mfail++ }
            }
        }
        if ($megaHits -gt 0) { W ("        Megabase verified {0} more file(s) that Modrinth did not know." -f $megaHits) 'DarkGray' }
    }
    Save-Cache $cache
    if ($failed) { if ($need.Count -gt 0 -and $versions.Count -eq 0 -and $out.Count -eq 0) { $state = 'unreachable' } else { $state = 'partial' } }
    return @{ State = $state; Map = $out }
}

# ---------------------------------------------------------------- archive scanning
function ToArr {
    param($X)
    if ($null -eq $X) { return , @() }
    if ($X -is [System.Collections.IList]) { $a = New-Object object[] $X.Count; $X.CopyTo($a, 0); return , $a }
    return , @($X)
}
function Register-Hit {
    param($Ctx, $Rule, [string]$Where, [string]$Loc)
    $h = $Ctx.Hits[$Rule.Id]
    if (-not $h) { $h = @{ Rule = $Rule; Name = 0; Content = 0; Locs = (New-Object System.Collections.Generic.List[string]) }; $Ctx.Hits[$Rule.Id] = $h }
    if ($Where -eq 'name') { $h.Name++ } else { $h.Content++ }
    if ($h.Locs.Count -lt 4 -and -not $h.Locs.Contains($Loc)) { [void]$h.Locs.Add($Loc) }
}
function Add-Ev {
    param($Ctx, [string]$Sev, [string]$Cat, [string]$Rule, [string]$Detail, [string]$Where = 'structure', [int]$Count = 1, $Locs = @(), [double]$Factor = 1.0, [bool]$Disc = $false)
    [void]$Ctx.Ev.Add([pscustomobject]@{
        Sev = $Sev; Category = $Cat; Rule = $Rule; Detail = $Detail; Where = $Where; Count = $Count
        Locations = (ToArr $Locs); Weight = [Math]::Round($SevW[$Sev] * $Factor, 1); Disc = $Disc })
}
function Get-EntryBytes {
    param($Entry, [int]$Max)
    $s = $Entry.Open()
    try {
        $ms = New-Object IO.MemoryStream
        $buf = New-Object byte[] 81920
        $t = 0
        while (($n = $s.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n); $t += $n; if ($t -ge $Max) { break } }
        return , $ms.ToArray()
    } finally { $s.Dispose() }
}
function Get-EntryHead {
    param($Entry)
    $s = $Entry.Open()
    try { $b = New-Object byte[] 8; $n = $s.Read($b, 0, 8); if ($n -lt 8) { $b = $b[0..([Math]::Max(0, $n - 1))] }; return , $b } finally { $s.Dispose() }
}
function Test-Magic {
    param($B, [string]$Ext, [string]$Full, $Ctx)
    if ($B.Length -lt 4) { return }
    if ($B[0] -eq 0xCA -and $B[1] -eq 0xFE -and $B[2] -eq 0xBA -and $B[3] -eq 0xBE -and $Ext -ne '.class' -and $Full -notmatch '\.SCL\.lombok$') {
        Add-Ev $Ctx 'high' 'Disguised content' 'Class file hidden under another extension' ("$Full is Java bytecode but named '$Ext'. Used to hide payloads from simple scanners.") 'structure' 1 @($Full)
    }
    if ($B[0] -eq 0x4D -and $B[1] -eq 0x5A) { [void]$Ctx.PE.Add($Full) }
    elseif ($B[0] -eq 0x7F -and $B[1] -eq 0x45 -and $B[2] -eq 0x4C -and $B[3] -eq 0x46) { [void]$Ctx.Natives.Add($Full) }
    elseif ($B[0] -eq 0x50 -and $B[1] -eq 0x4B -and $B[2] -eq 3 -and $B[3] -eq 4 -and $Ext -ne '.jar' -and $Ext -ne '.zip') {
        [void]$Ctx.HiddenZips.Add($Full)
    }
}
function Test-SkipPrefix { param([string]$N) foreach ($p in $SkipPrefixes) { if ($N.StartsWith($p, [StringComparison]::Ordinal)) { return $true } } return $false }

function ConvertFrom-Fullwidth {
    param([string]$T)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $T.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 0xFF01 -and $c -le 0xFF5E) { [void]$sb.Append([char]($c - 0xFEE0)) }
        elseif ($c -eq 0x3000 -or $c -eq 32) { }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}
function Scan-Content {
    param([string]$Text, [string]$Loc, $Ctx, [bool]$IsCp)
    $n = 0
    foreach ($m in $TermRegex.Matches($Text)) {
        $r = $script:TermIndex[$m.Value.ToLower()]
        if ($r) { Register-Hit $Ctx $r 'content' $Loc }
        $n++; if ($n -gt 300) { break }
    }
    $n = 0
    $rx = $ExactRegex; if (-not $IsCp) { $rx = $ExactLoose }
    foreach ($m in $rx.Matches($Text)) {
        $r = $script:ExactIndex[$m.Value]
        if ($r) { Register-Hit $Ctx $r 'content' $Loc }
        $n++; if ($n -gt 300) { break }
    }
    $n = 0
    foreach ($m in $WordRegex.Matches($Text)) {
        $r = $script:WordIndex[$m.Value]
        if ($r) { Register-Hit $Ctx $r 'content' $Loc }
        $n++; if ($n -gt 200) { break }
    }
    $fwm = $FwRegex.Matches($Text)
    if ($fwm.Count -gt 0) {
        $n = 0
        foreach ($m in $fwm) {
            $n++; if ($n -gt 60) { break }
            $norm = ''
            $norm = ConvertFrom-Fullwidth $m.Value
            if (-not $norm) { continue }
            if ($Ctx.Fullwidth.Count -lt 25 -and -not $Ctx.Fullwidth.Contains($norm)) { [void]$Ctx.Fullwidth.Add($norm) }
            foreach ($t in $TermRegex.Matches($norm)) { $r = $script:TermIndex[$t.Value.ToLower()]; if ($r) { Register-Hit $Ctx $r 'content' ($Loc + ' (fullwidth)') } }
            foreach ($t in $WordRegex.Matches($norm)) { $r = $script:WordIndex[$t.Value]; if ($r) { Register-Hit $Ctx $r 'content' ($Loc + ' (fullwidth)') } }
        }
    }
    if ($Text.IndexOf('webhooks', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        foreach ($m in $HookRegex.Matches($Text)) { if ($Ctx.Webhooks.Count -lt 3) { [void]$Ctx.Webhooks.Add($Loc) } }
    }
    if ($Text.IndexOf('http', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $n = 0
        foreach ($m in $UrlRegex.Matches($Text)) {
            $h = $m.Groups[1].Value.ToLower().TrimEnd('.')
            if (-not $Ctx.Hosts.ContainsKey($h)) { $Ctx.Hosts[$h] = $m.Value }
            $n++; if ($n -gt 40) { break }
        }
    }
}

function Parse-Meta {
    param([string]$Name, [string]$Text)
    $m = @{ Loader = ''; Id = ''; Name = ''; Version = ''; Authors = ''; Description = '' }
    try {
        if ($Name -eq 'fabric.mod.json') {
            $j = $Text | ConvertFrom-Json
            $m.Loader = 'Fabric'; $m.Id = [string]$j.id; $m.Name = [string]$j.name; $m.Version = [string]$j.version; $m.Description = [string]$j.description
            $m.Authors = (@($j.authors) | ForEach-Object { if ($_.name) { $_.name } else { [string]$_ } }) -join ', '
        } elseif ($Name -eq 'quilt.mod.json') {
            $j = $Text | ConvertFrom-Json
            $m.Loader = 'Quilt'; $m.Id = [string]$j.quilt_loader.id; $m.Version = [string]$j.quilt_loader.version
            $m.Name = [string]$j.quilt_loader.metadata.name; $m.Description = [string]$j.quilt_loader.metadata.description
        } elseif ($Name -like '*mods.toml') {
            $m.Loader = 'Forge/NeoForge'
            if ($Text -match '(?m)^\s*modId\s*=\s*"([^"]+)"') { $m.Id = $Matches[1] }
            if ($Text -match '(?m)^\s*version\s*=\s*"([^"]+)"') { $m.Version = $Matches[1] }
            if ($Text -match '(?m)^\s*displayName\s*=\s*"([^"]+)"') { $m.Name = $Matches[1] }
            if ($Text -match '(?m)^\s*authors\s*=\s*"([^"]+)"') { $m.Authors = $Matches[1] }
        } elseif ($Name -eq 'mcmod.info') {
            $j = $Text | ConvertFrom-Json
            $x = @($j)[0]; if ($x.modList) { $x = @($x.modList)[0] }
            $m.Loader = 'Forge (legacy)'; $m.Id = [string]$x.modid; $m.Name = [string]$x.name; $m.Version = [string]$x.version
            $m.Authors = (@($x.authorList) -join ', ')
        }
    } catch {}
    return $m
}

function Scan-Archive {
    param($Zip, [string]$Prefix, [int]$Level, $Ctx)
    $seen = @{}
    $maxBytes = [int]([Math]::Min(2000, $MaxEntryMB) * 1MB)
    $nestMax = 1; if ($Depth -eq 'Deep') { $nestMax = 3 }
    foreach ($entry in $Zip.Entries) {
        $name = $entry.FullName
        if ([string]::IsNullOrEmpty($name) -or $name.EndsWith('/')) { continue }
        $full = $Prefix + $name
        $Ctx.Entries++
        $lname = $name.ToLower()
        $di = $lname.LastIndexOf('.'); $ext = ''
        if ($di -ge 0 -and $di -gt $lname.LastIndexOf('/')) { $ext = $lname.Substring($di) }
        try {
            if ($seen.ContainsKey($lname)) { $Ctx.Dupes++ } else { $seen[$lname] = 1 }
            if ($name -match '(^|[/\\])\.\.([/\\]|$)' -or $name.StartsWith('/') -or $name -match '^[A-Za-z]:') { [void]$Ctx.Traversal.Add($full) }
            if ($entry.CompressedLength -gt 0 -and $entry.Length -gt 50MB -and ($entry.Length / $entry.CompressedLength) -gt 200) { $Ctx.Bomb++ }

            foreach ($m in $TermRegex.Matches($full)) { $r = $script:TermIndex[$m.Value.ToLower()]; if ($r) { Register-Hit $Ctx $r 'name' $full } }
            foreach ($m in $WordRegex.Matches($full)) { $r = $script:WordIndex[$m.Value]; if ($r) { Register-Hit $Ctx $r 'name' $full } }
            $om = $ObfRegex.Match($full); if ($om.Success) { [void]$Ctx.ObfSigs.Add($om.Value) }

            if ($ext -eq '.class') {
                $Ctx.ClassTotal++
                if ($Level -eq 0) { [void]$Ctx.ClassNames.Add($name.Substring(0, $name.Length - 6)) }
                if ($Depth -eq 'Quick') { continue }
                if ($entry.Length -gt $maxBytes) { $Ctx.Big++; continue }
                $bytes = Get-EntryBytes $entry $maxBytes
                $magicOk = ($bytes.Length -ge 4 -and $bytes[0] -eq 0xCA -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0xBA -and $bytes[3] -eq 0xBE)
                if (-not $magicOk) { [void]$Ctx.BadClass.Add($full); continue }
                if (($Depth -ne 'Deep') -and (Test-SkipPrefix $name)) { continue }
                if ($Native) { $cp = [OnyxNative]::ConstantPool($bytes); $isCp = $true }
                else { $cp = [Text.Encoding]::GetEncoding(28591).GetString($bytes); $isCp = $false }
                if ($cp) { Scan-Content $cp $full $Ctx $isCp }
                if ($Depth -eq 'Deep' -and $Native -and $bytes.Length -gt 4096) {
                    if ([OnyxNative]::Entropy($bytes, 32768) -gt 7.4) { [void]$Ctx.HighEntropy.Add($full) }
                }
                continue
            }

            if ($ext -eq '.jar') {
                $inStd = $name.StartsWith('META-INF/jars/') -or $name.StartsWith('META-INF/libraries/')
                if (-not $inStd -and $Level -eq 0) { [void]$Ctx.OddJars.Add($full) }
                if ($Level -lt $nestMax -and $Depth -ne 'Quick' -and $entry.Length -le 64MB) {
                    $nb = Get-EntryBytes $entry 67108864
                    $sh = ([BitConverter]::ToString(([Security.Cryptography.SHA1]::Create()).ComputeHash($nb))).Replace('-', '').ToLower()
                    [void]$Ctx.Nested.Add([pscustomobject]@{ Path = $full; SizeBytes = $nb.Length; SHA1 = $sh })
                    $nz = $null
                    try {
                        $nz = New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream(, $nb)), [IO.Compression.ZipArchiveMode]::Read)
                        Scan-Archive $nz ($full + '!/') ($Level + 1) $Ctx
                    } catch { $Ctx.Unreadable++ } finally { if ($nz) { $nz.Dispose() } }
                } else {
                    [void]$Ctx.Nested.Add([pscustomobject]@{ Path = $full; SizeBytes = $entry.Length; SHA1 = '' })
                }
                continue
            }

            if ($ScriptExts -contains $ext) { [void]$Ctx.Scripts.Add($full) }
            if ($NativeExts -contains $ext) { [void]$Ctx.Natives.Add($full) }

            $isText = ($TextExts -contains $ext) -or ($name -eq 'META-INF/MANIFEST.MF')
            if ($isText -and $entry.Length -le 4MB -and $Depth -ne 'Quick') {
                $bytes = Get-EntryBytes $entry 4194304
                Test-Magic $bytes $ext $full $Ctx
                $text = [Text.Encoding]::UTF8.GetString($bytes)
                $base = $name; if ($name.Contains('/')) { $base = $name.Substring($name.LastIndexOf('/') + 1) }
                if ($name -eq 'fabric.mod.json' -or $name -eq 'quilt.mod.json' -or $name -eq 'mcmod.info' -or $name -like 'META-INF/*mods.toml') {
                    $pm = Parse-Meta $(if ($name -like '*mods.toml') { 'mods.toml' } else { $name }) $text
                    if ($pm.Id) { [void]$Ctx.AllMeta.Add(@{ Level = $Level; Meta = $pm; Path = $full }) }
                }
                if ($name -eq 'META-INF/MANIFEST.MF') {
                    foreach ($ln in ($text -split "`r?`n")) {
                        if ($ln -match '^(Premain-Class|Agent-Class|Launcher-Agent-Class|Can-Redefine-Classes|Can-Retransform-Classes|Boot-Class-Path|Main-Class):\s*(.+)$') { $Ctx.Manifest[$Matches[1]] = $Matches[2].Trim() }
                    }
                }
                if ($name.StartsWith('META-INF/') -or $name -eq 'META-INF/MANIFEST.MF') { $om = $ObfRegex.Match($text); if ($om.Success) { [void]$Ctx.ObfSigs.Add($om.Value) } }
                Scan-Content $text $full $Ctx $false
                continue
            }
            if ($entry.Length -gt 0 -and $Depth -ne 'Quick') {
                $hd = Get-EntryHead $entry
                Test-Magic $hd $ext $full $Ctx
                if ($Depth -eq 'Deep' -and $Native -and $entry.Length -gt 4096 -and $entry.Length -le 4MB -and ($ext -eq '.dat' -or $ext -eq '.bin' -or $ext -eq '')) {
                    $bb = Get-EntryBytes $entry 4194304
                    if ([OnyxNative]::Entropy($bb, 32768) -gt 7.6) { [void]$Ctx.HighEntropy.Add($full) }
                }
            }
        } catch { $Ctx.Unreadable++ }
    }
}

function Test-HostClass {
    param([string]$H)
    if ($H -match 'api\.telegram\.org$') { return 'telegram' }
    if ($H -match '(^|\.)(cdn\.discordapp\.com|media\.discordapp\.net)$') { return 'discordcdn' }
    if ($H -match $PayloadHostRegex) { return 'payload' }
    if ($H -match $TunnelHostRegex) { return 'tunnel' }
    if ($H -match '^\d{1,3}(\.\d{1,3}){3}$') {
        if ($H -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)') { return 'trusted' }
        return 'ip'
    }
    if ($H -match $TrustedHostRegex) { return 'trusted' }
    foreach ($t in $Cfg.TrustedDomains) { if ($H -eq $t -or $H.EndsWith('.' + $t)) { return 'trusted' } }
    return 'other'
}

function Build-Evidence {
    param($Ctx, $Zone, [string]$FileName, [bool]$VerifiedHint)
    # 1) rule hits
    foreach ($k in $Ctx.Hits.Keys) {
        $h = $Ctx.Hits[$k]; $r = $h.Rule
        if ($r.Hidden) { continue }
        $factor = 1.0; $where = 'name'
        if ($h.Name -eq 0) { $where = 'content'; if ($r.Kind -ne 'exact') { $factor = 0.6 } }
        $cnt = $h.Name + $h.Content
        Add-Ev $Ctx $r.Sev $r.Cat $r.Term ("{0}. Seen {1} time(s), first in: {2}" -f $r.Note, $cnt, $h.Locs[0]) $where $cnt $h.Locs $factor $true
    }
    # 2) behavioural combinations
    $Hs = { param($id) $Ctx.Hits.ContainsKey($id) }
    $exec = (& $Hs 'e:java/lang/processbuilder') -or ((& $Hs 'e:java/lang/runtime') -and (& $Hs 'e:exec'))
    $lol = $false
    foreach ($id in @('t:powershell','t:certutil','t:bitsadmin','t:mshta','t:wscript','t:regsvr32','t:rundll32','t:schtasks','t:encodedcommand','t:invoke-webrequest','t:downloadfile','t:downloadstring','t:cmd.exe')) { if (& $Hs $id) { $lol = $true } }
    if ($exec -and $lol) { Add-Ev $Ctx 'critical' 'Behaviour combination' 'Process execution + system download tools' 'Code can spawn processes AND references PowerShell/cmd/certutil-style tooling: classic dropper pattern.' 'content' 1 @() 1.0 $true }
    $remoteHosts = @($Ctx.Hosts.Keys | Where-Object { (Test-HostClass $_) -ne 'trusted' })
    if (((& $Hs 'e:java/net/urlclassloader') -or (& $Hs 'e:defineclass')) -and $remoteHosts.Count -gt 0) {
        Add-Ev $Ctx 'high' 'Behaviour combination' 'Remote code loading pattern' ('Dynamic class loading together with external hosts: ' + (($remoteHosts | Select-Object -First 4) -join ', ')) 'content' 1 @() 1.0 $true
    }
    if ((& $Hs 'e:java/awt/robot') -and (& $Hs 'e:mousepress')) { Add-Ev $Ctx 'high' 'Behaviour combination' 'Synthetic mouse input (AutoClicker pattern)' 'java.awt.Robot with mousePress: typical of external auto-clickers.' 'content' 1 @() 1.0 $true }
    if ((& $Hs 'e:javax/crypto/cipher') -and (& $Hs 'e:java/util/base64') -and (& $Hs 'e:defineclass')) { Add-Ev $Ctx 'high' 'Behaviour combination' 'Encrypted payload loader pattern' 'Cipher + Base64 + defineClass together: decrypts and loads hidden classes.' 'content' 1 @() 1.0 $true }
    if ((& $Hs 't:leveldb') -and ((& $Hs 't:discordcanary') -or (& $Hs 't:discordptb'))) { Add-Ev $Ctx 'critical' 'Behaviour combination' 'Discord token theft pattern' 'References Discord client storage (leveldb + Discord variants).' 'content' 1 @() 1.0 $true }
    if ($Ctx.Webhooks.Count -gt 0) { Add-Ev $Ctx 'critical' 'Network exfiltration' 'Discord webhook URL embedded' 'Hard-coded Discord webhook: the standard channel for sending stolen data out.' 'content' $Ctx.Webhooks.Count $Ctx.Webhooks 1.0 $true }
    # 3) hosts
    $groups = @{ telegram = @(); discordcdn = @(); payload = @(); tunnel = @(); ip = @(); other = @() }
    foreach ($h in $Ctx.Hosts.Keys) { $c = Test-HostClass $h; if ($c -ne 'trusted') { $groups[$c] += $h } }
    if ($groups.telegram.Count) { Add-Ev $Ctx 'high' 'Network endpoint' 'Telegram bot API' ($groups.telegram -join ', ') 'content' $groups.telegram.Count @() 1.0 $true }
    if ($groups.discordcdn.Count) { Add-Ev $Ctx 'high' 'Network endpoint' 'Discord CDN payload host' ($groups.discordcdn -join ', ') 'content' $groups.discordcdn.Count @() 1.0 $true }
    if ($groups.payload.Count) { Add-Ev $Ctx 'medium' 'Network endpoint' 'Paste / file-host endpoint' (($groups.payload | Select-Object -First 6) -join ', ') 'content' $groups.payload.Count @() 1.0 $true }
    if ($groups.tunnel.Count) { Add-Ev $Ctx 'medium' 'Network endpoint' 'Tunnel / dynamic-DNS endpoint' (($groups.tunnel | Select-Object -First 6) -join ', ') 'content' $groups.tunnel.Count @() 1.0 $true }
    if ($groups.ip.Count) { Add-Ev $Ctx 'medium' 'Network endpoint' 'Hard-coded IP address endpoint' (($groups.ip | Select-Object -First 6) -join ', ') 'content' $groups.ip.Count @() 1.0 $true }
    if ($groups.other.Count) { Add-Ev $Ctx 'info' 'Network endpoint' 'Contacts other external hosts' (($groups.other | Select-Object -First 10) -join ', ') 'content' $groups.other.Count @() 1.0 $true }
    # 4) structure
    foreach ($k in @('Premain-Class','Agent-Class','Launcher-Agent-Class')) {
        if ($Ctx.Manifest.ContainsKey($k) -and ([string]$Ctx.Manifest[$k]) -notmatch '^lombok\.') { Add-Ev $Ctx 'high' 'Java agent' 'Manifest declares a Java agent' ("$k = " + $Ctx.Manifest[$k]) 'structure' 1 @('META-INF/MANIFEST.MF') 1.0 $true }
    }
    if ($Ctx.PE.Count) { Add-Ev $Ctx 'high' 'Bundled binary' 'Embedded Windows executable (PE)' (($Ctx.PE | Select-Object -First 4) -join '; ') 'structure' $Ctx.PE.Count $Ctx.PE 1.0 $false }
    $nat = @($Ctx.Natives | Where-Object { $Ctx.PE -notcontains $_ })
    if ($nat.Count) { Add-Ev $Ctx 'medium' 'Bundled binary' 'Native libraries bundled' (($nat | Select-Object -First 4) -join '; ') 'structure' $nat.Count $nat 1.0 $false }
    if ($Ctx.Scripts.Count) { Add-Ev $Ctx 'medium' 'Bundled binary' 'Script / shortcut files bundled' (($Ctx.Scripts | Select-Object -First 4) -join '; ') 'structure' $Ctx.Scripts.Count $Ctx.Scripts 1.0 $false }
    if ($Ctx.HiddenZips.Count) { Add-Ev $Ctx 'medium' 'Disguised content' 'Archive hidden inside non-archive file' (($Ctx.HiddenZips | Select-Object -First 4) -join '; ') 'structure' $Ctx.HiddenZips.Count $Ctx.HiddenZips 1.0 $false }
    if ($Ctx.Fullwidth.Count -ge 3) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Fullwidth Unicode labels' ('Fullwidth Latin strings hide labels from plain-text search (shown normalized): ' + (($Ctx.Fullwidth | Select-Object -First 5) -join ', ')) 'content' $Ctx.Fullwidth.Count $Ctx.Fullwidth 1.0 $true }
    if ($Ctx.Nested.Count -eq 1 -and $Ctx.ClassNames.Count -lt 3) { Add-Ev $Ctx 'medium' 'Structure' 'Hollow shell mod' ("Only $($Ctx.ClassNames.Count) own class(es) wrapping a single nested JAR: " + $Ctx.Nested[0].Path) 'structure' 1 @($Ctx.Nested[0].Path) 1.0 $true }
    $oddNames = @()
    foreach ($nj in $Ctx.Nested) {
        $nb = [IO.Path]::GetFileNameWithoutExtension(($nj.Path -split '[/!]')[-1])
        if ($nb.Length -gt 0 -and $nb.Length -le 20 -and $nb -notmatch '\d' -and $nb -notmatch '^(com|org|net|io|dev|gs|xyz|app|me|tv|uk|be|fr|de)_') { $oddNames += $nb }
    }
    if ($oddNames.Count) { Add-Ev $Ctx 'low' 'Structure' 'Nested JAR without version' ('Unversioned bundled dependency: ' + (($oddNames | Select-Object -First 4) -join ', ')) 'structure' $oddNames.Count @() 1.0 $true }
    if ($Ctx.OddJars.Count) { Add-Ev $Ctx 'medium' 'Disguised content' 'JAR outside META-INF/jars' (($Ctx.OddJars | Select-Object -First 4) -join '; ') 'structure' $Ctx.OddJars.Count $Ctx.OddJars 1.0 $false }
    if ($Ctx.BadClass.Count) { Add-Ev $Ctx 'high' 'Disguised content' 'Invalid .class files (scrambled / encrypted?)' ('Missing CAFEBABE header: ' + (($Ctx.BadClass | Select-Object -First 3) -join '; ')) 'structure' $Ctx.BadClass.Count $Ctx.BadClass 1.0 $false }
    if ($Ctx.Traversal.Count) { Add-Ev $Ctx 'high' 'Archive tricks' 'Path-traversal entry names' (($Ctx.Traversal | Select-Object -First 3) -join '; ') 'structure' $Ctx.Traversal.Count $Ctx.Traversal 1.0 $false }
    if ($Ctx.Dupes -gt 0) { Add-Ev $Ctx 'medium' 'Archive tricks' 'Duplicate entry names' ("$($Ctx.Dupes) duplicate entries: different tools may read different versions.") 'structure' $Ctx.Dupes @() 1.0 $false }
    if ($Ctx.Bomb -gt 0) { Add-Ev $Ctx 'medium' 'Archive tricks' 'Extreme compression ratio' 'Entry expands more than 200x (possible zip bomb).' 'structure' $Ctx.Bomb @() 1.0 $false }
    if ($Ctx.HighEntropy.Count) { Add-Ev $Ctx 'medium' 'Disguised content' 'High-entropy data (encrypted or packed)' (($Ctx.HighEntropy | Select-Object -First 4) -join '; ') 'structure' $Ctx.HighEntropy.Count $Ctx.HighEntropy 1.0 $true }
    if ($Ctx.Unreadable -gt 0) { Add-Ev $Ctx 'low' 'Archive tricks' 'Unreadable entries' ("$($Ctx.Unreadable) entries could not be read.") 'structure' $Ctx.Unreadable @() 1.0 $false }
    if ($Ctx.Big -gt 0) { Add-Ev $Ctx 'info' 'Coverage' 'Oversized classes skipped' ("$($Ctx.Big) class files exceeded the size limit (-MaxEntryMB).") 'structure' $Ctx.Big @() 1.0 $false }
    # 5) obfuscation (top-level classes only)
    $n = $Ctx.ClassNames.Count
    $stats = @{ Classes = $Ctx.ClassTotal; Entries = $Ctx.Entries; ShortPct = 0; ConfusionPct = 0; UnicodePct = 0 }
    if ($n -gt 0) {
        $sh = 0; $cf = 0; $un = 0; $nu = 0; $fw = 0; $jp = 0; $nv = 0; $sp = 0
        foreach ($cn in $Ctx.ClassNames) {
            $s = $cn.Substring($cn.LastIndexOf('/') + 1).Split('$')[0]
            if ($s -eq 'module-info' -or $s -eq 'package-info') { continue }
            if ($s.Length -le 2) { $sh++ }
            if ($s.Length -ge 3 -and $s -cmatch '^[Il1O0_]+$') { $cf++ }
            if ($s -match '[^\u0000-\u007F]') { $un++ }
            if ($s -match '^\d+$') { $nu++ }
            if ($s -match '[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]') { $fw++ }
            if ($s -match '[\u3040-\u309F\u30A0-\u30FF]') { $jp++ }
            if ($s.Length -ge 3 -and $s.Length -le 8 -and $s -match '^[A-Za-z]+$' -and $s -notmatch '[aeiouAEIOU]') { $nv++ }
            $parts = $cn.Split('/')
            for ($pi = 0; $pi -lt ($parts.Count - 1); $pi++) { if ($parts[$pi].Length -eq 1) { $sp++ } }
        }
        $stats.ShortPct = [Math]::Round(100.0 * $sh / $n, 1); $stats.ConfusionPct = [Math]::Round(100.0 * $cf / $n, 1); $stats.UnicodePct = [Math]::Round(100.0 * $un / $n, 1)
        if ($n -ge 15) {
            if ($stats.ShortPct -ge 55) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Short class names' ("$($stats.ShortPct)% of classes have 1-2 character names.") 'structure' 1 @() 1.0 $true }
            if ($stats.ConfusionPct -ge 10) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Look-alike class names (I/l/1/O/0/_)' ("$($stats.ConfusionPct)% of classes use confusing names.") 'structure' 1 @() 1.0 $true }
        }
        $stats.NumericPct = [Math]::Round(100.0 * $nu / $n, 1); $stats.JapaneseClasses = $jp; $stats.FullwidthClasses = $fw
        if ($n -ge 15 -and $stats.NumericPct -ge 20) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Numeric class names' ("$($stats.NumericPct)% of classes have digit-only names (automated obfuscator trait).") 'structure' 1 @() 1.0 $true }
        if ($fw -gt 0) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Fullwidth Unicode class names' ("$fw class name(s) use fullwidth letters.") 'structure' $fw @() 1.0 $true }
        if ($jp -ge 2) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Japanese kana class names' ("$jp class name(s) are hiragana/katakana (a known obfuscator style).") 'structure' $jp @() 1.0 $true }
        if ($n -ge 15 -and (100.0 * $nv / $n) -ge 10) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Gibberish class names (no vowels)' ("$nv of $n classes are short vowel-less names.") 'structure' $nv @() 1.0 $true }
        if ($sp -ge 6) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Single-character package paths' ("$sp package segments like a/b/c.") 'structure' $sp @() 1.0 $true }
        if ($stats.UnicodePct -gt 0) { Add-Ev $Ctx 'medium' 'Obfuscation' 'Non-ASCII class names' ("$($stats.UnicodePct)% of classes use non-ASCII names (obfuscator trait; some non-English mods do too).") 'structure' 1 @() 1.0 $true }
    }
    foreach ($s in @($Ctx.ObfSigs | Select-Object -Unique)) { Add-Ev $Ctx 'low' 'Obfuscation' "Obfuscator signature: $s" 'Named in entry names or manifest. Commercial obfuscators are also used by legitimate authors.' 'structure' 1 @() 1.0 $true }
    return $stats
}

function Analyze-Mod {
    param($File, $Hashes, $MrMap, [string]$Root)
    $ctx = @{
        Hits = @{}; Ev = (New-Object System.Collections.Generic.List[object]); Hosts = @{}
        ClassNames = (New-Object System.Collections.Generic.List[string]); Nested = (New-Object System.Collections.Generic.List[object])
        AllMeta = (New-Object System.Collections.Generic.List[object]); Manifest = @{}; ObfSigs = (New-Object System.Collections.Generic.List[string])
        PE = (New-Object System.Collections.Generic.List[string]); Natives = (New-Object System.Collections.Generic.List[string])
        Scripts = (New-Object System.Collections.Generic.List[string]); HiddenZips = (New-Object System.Collections.Generic.List[string])
        OddJars = (New-Object System.Collections.Generic.List[string]); BadClass = (New-Object System.Collections.Generic.List[string])
        Traversal = (New-Object System.Collections.Generic.List[string]); HighEntropy = (New-Object System.Collections.Generic.List[string])
        Webhooks = (New-Object System.Collections.Generic.List[string]); Fullwidth = (New-Object System.Collections.Generic.List[string])
        Entries = 0; ClassTotal = 0; Dupes = 0; Bomb = 0; Big = 0; Unreadable = 0
    }
    $fs = $null; $zip = $null; $archiveOk = $false
    try {
        $fs = New-Object IO.FileStream($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $head = New-Object byte[] 4; [void]$fs.Read($head, 0, 4); [void]$fs.Seek(0, [IO.SeekOrigin]::Begin)
        if ($head[0] -eq 0x4D -and $head[1] -eq 0x5A) { Add-Ev $ctx 'critical' 'Disguised content' 'Windows executable disguised as a JAR' 'File starts with MZ (PE header), not a ZIP/JAR header.' }
        $zip = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read)
        $archiveOk = $true
        Scan-Archive $zip '' 0 $ctx
    } catch {
        if (-not $archiveOk) { Add-Ev $ctx 'high' 'Archive tricks' 'Not a readable ZIP/JAR archive' 'Corrupt, truncated, or not actually a JAR.' }
    } finally { if ($zip) { $zip.Dispose() }; if ($fs) { $fs.Dispose() } }

    $stats = Build-Evidence $ctx $null $File.Name $false

    # metadata
    $meta = $null
    foreach ($pref in @('Fabric','Quilt','Forge/NeoForge','Forge (legacy)')) {
        foreach ($x in $ctx.AllMeta) { if ($x.Level -eq 0 -and $x.Meta.Loader -eq $pref -and -not $meta) { $meta = $x.Meta } }
    }
    $nestedIds = @($ctx.AllMeta | Where-Object { $_.Level -gt 0 } | ForEach-Object { $_.Meta.Id })
    if ($archiveOk -and -not $meta -and $Depth -ne 'Quick') {
        if ($ctx.ClassTotal -gt 0) { Add-Ev $ctx 'low' 'Structure' 'No mod metadata' 'No fabric.mod.json / mods.toml / mcmod.info found (a library jar, or hand-built).' }
        else { Add-Ev $ctx 'low' 'Structure' 'Archive has no classes' 'The JAR contains no .class files.' }
    }
    if ($meta -and $meta.Id) {
        $n1 = ($File.Name.ToLower() -replace '[^a-z0-9]', ''); $n2 = ($meta.Id.ToLower() -replace '[^a-z0-9]', '')
        if ($n2.Length -ge 3 -and -not $n1.Contains($n2) -and -not $n1.Contains(($meta.Name.ToLower() -replace '[^a-z0-9]', ''))) {
            Add-Ev $ctx 'low' 'Structure' 'File name does not match mod id' ("File is '$($File.Name)' but declares mod id '$($meta.Id)'. Renamed jars are a common way to hide cheats.")
        }
    }

    # zone / ADS / verification
    $zone = Get-ZoneInfo $File.FullName
    $sha1 = $Hashes.Sha1
    $mr = $null; if ($sha1 -and $MrMap.ContainsKey($sha1)) { $mr = $MrMap[$sha1] }
    $allow = ($Cfg.AllowSha1 -contains $sha1)
    $verified = ($null -ne $mr) -or $allow
    if ($zone.Hot) { Add-Ev $ctx 'high' 'Download origin' ('Downloaded from ' + $zone.Name) 'Origin is a known cheat-client site or a remote-access tool.' }
    if ($zone.Flag -and -not $verified) { Add-Ev $ctx 'low' 'Download origin' ("Downloaded from " + $zone.Name) 'File-sharing hosts are a common distribution route for cheat jars. Not proof of anything by itself.' }
    try {
        foreach ($s in @(Get-Item -LiteralPath $File.FullName -Stream * -ErrorAction SilentlyContinue)) {
            if ($s.Stream -ne ':$DATA' -and $s.Stream -ne 'Zone.Identifier') { Add-Ev $ctx 'high' 'Archive tricks' 'Alternate data stream attached' ("NTFS stream '$($s.Stream)' ($($s.Length) bytes) is hidden from normal file listings.") }
        }
    } catch {}
    if ($File.Attributes -band [IO.FileAttributes]::Hidden) { Add-Ev $ctx 'medium' 'Structure' 'Hidden file attribute set' 'The jar is hidden in Explorer.' }

    $mrObj = $null
    if ($mr) {
        $mrObj = [pscustomobject]@{
            Project = $mr.project_id; Title = $mr.title; Slug = $mr.slug; Version = $mr.version_number; VersionName = $mr.version_name
            Downloads = $mr.downloads; Published = $mr.published; Loaders = @($mr.loaders); GameVersions = @($mr.game_versions)
            Url = $(if ($mr.slug) { 'https://modrinth.com/project/' + $mr.slug } elseif ($mr.project_id) { 'https://modrinth.com/project/' + $mr.project_id } else { '' })
        }
    }
    $rel = $File.FullName; if ($rel.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) { $rel = $rel.Substring($Root.Length).TrimStart('\', '/') }
    $evs = @($ctx.Ev | Sort-Object { -$_.Weight })
    $mod = [pscustomobject]@{
        File = $File.Name; RelPath = $rel; Path = $File.FullName; SizeBytes = $File.Length; Disabled = ($File.Name -match '\.disabled$')
        Created = (Iso $File.CreationTime); Modified = (Iso $File.LastWriteTime); SHA1 = $sha1; SHA256 = $Hashes.Sha256
        Status = 'UNKNOWN'; Risk = 'LOW'; Score = 0; Verified = $verified; VerifiedBy = $(if ($mr) { $(if ($mr.source) { [string]$mr.source } else { 'Modrinth' }) } elseif ($allow) { 'Allowlist' } else { '' })
        Source = $zone.Name; SourceUrl = $zone.Url; Modrinth = $mrObj
        Meta = $(if ($meta) { [pscustomobject]$meta } else { $null })
        Evidence = $evs; Urls = @($ctx.Hosts.Keys | Sort-Object | Select-Object -First 30)
        NestedJars = (ToArr $ctx.Nested); NestedModIds = @($nestedIds | Select-Object -Unique)
        Stats = [pscustomobject]$stats
    }
    Set-Verdict $mod
    return $mod
}

function Set-Verdict {
    param($M)
    $sum = 0.0; $crit = $false; $obf = $false; $non = 0
    foreach ($e in $M.Evidence) {
        $w = [double]$e.Weight; $disc = ($M.Verified -and $e.Disc)
        if ($disc) { $w = $w * 0.25 }
        $sum += $w
        if ($e.Sev -eq 'critical' -and -not $disc) { $crit = $true }
        if ($e.Category -eq 'Obfuscation') { $obf = $true } elseif ($e.Weight -ge 8) { $non++ }
    }
    $score = [int][Math]::Min(100, [Math]::Round($sum))
    if ($M.Verified) {
        if ($score -ge 30 -or $crit) { $st = 'REVIEW' } else { $st = 'VERIFIED' }
    } else {
        if ($crit -or $score -ge 60) { $st = 'CRITICAL' }
        elseif ($score -ge 30) { $st = 'SUSPICIOUS' }
        elseif ($score -ge 8 -and $non -gt 0) { $st = 'REVIEW' }
        elseif ($obf) { $st = 'OBFUSCATED' }
        else { $st = 'UNKNOWN' }
    }
    $risk = @{ VERIFIED = 'LOW'; UNKNOWN = 'LOW'; OBFUSCATED = 'MEDIUM'; REVIEW = 'MEDIUM'; SUSPICIOUS = 'HIGH'; CRITICAL = 'CRITICAL' }[$st]
    $M.Score = $score; $M.Status = $st; $M.Risk = $risk
}

# ---------------------------------------------------------------- folder + JVM + log checks
function Get-FolderIssues {
    param($Others)
    $out = New-Object System.Collections.Generic.List[object]
    $risky = @('.exe','.dll','.bat','.cmd','.ps1','.vbs','.vbe','.scr','.msi','.lnk','.js','.jse','.hta')
    foreach ($f in $Others) {
        $ext = $f.Extension.ToLower()
        $hdr = $null
        try { $fs = [IO.File]::OpenRead($f.FullName); $b = New-Object byte[] 4; [void]$fs.Read($b, 0, 4); $fs.Dispose(); $hdr = $b } catch {}
        if ($hdr -and $hdr[0] -eq 0x4D -and $hdr[1] -eq 0x5A) {
            [void]$out.Add([pscustomobject]@{ Sev = 'high'; Title = 'Windows executable inside mods folder'; Detail = "$($f.Name) has a PE header (extension '$ext')."; File = $f.FullName })
        } elseif ($risky -contains $ext) {
            [void]$out.Add([pscustomobject]@{ Sev = 'high'; Title = 'Executable / script inside mods folder'; Detail = "$($f.Name) has no business being next to mods."; File = $f.FullName })
        } elseif ($f.Attributes -band [IO.FileAttributes]::Hidden) {
            [void]$out.Add([pscustomobject]@{ Sev = 'medium'; Title = 'Hidden file in mods folder'; Detail = $f.Name; File = $f.FullName })
        } elseif ($hdr -and $hdr[0] -eq 0x50 -and $hdr[1] -eq 0x4B -and $ext -ne '.zip') {
            [void]$out.Add([pscustomobject]@{ Sev = 'medium'; Title = 'Archive with a non-archive extension'; Detail = "$($f.Name) is a ZIP/JAR renamed to '$ext'. Minecraft will not load it, but it can be renamed back."; File = $f.FullName })
        }
    }
    return $out
}

function Get-JavaRuntime {
    $out = @()
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue)
    $flagRx = '(?i)(-javaagent:[^\s"]+|-agentlib:[^\s"]+|-agentpath:[^\s"]+|-Xbootclasspath[/a-z]*:[^\s"]+|-Xverify:none|-noverify|-XX:\+DisableAttachMechanism|-Djava\.system\.class\.loader=[^\s"]+|-Dfabric\.addMods=[^\s"]+|-Dfabric\.classPathGroups=[^\s"]+)'
    foreach ($p in $procs) {
        $cmd = [string]$p.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        if ($cmd -notmatch '(?i)minecraft|fabric|forge|quilt|lwjgl|net\.minecraft') { continue }
        $agent = @(); $risky = @()
        foreach ($m in [regex]::Matches($cmd, $flagRx)) {
            if ($m.Value -match '(?i)^-(javaagent|agentlib|agentpath|xbootclasspath)') { $agent += $m.Value } else { $risky += $m.Value }
        }
        $agentFiles = @()
        foreach ($a in $agent) {
            if ($a -match '(?i)^-javaagent:([^=]+)') {
                $ap = $Matches[1].Trim('"')
                if (Test-Path -LiteralPath $ap) { $agentFiles += [pscustomobject]@{ Path = $ap; SHA1 = (Get-Hashes $ap).Sha1 } }
            }
        }
        $tmpMods = @()
        try {
            foreach ($mo in @((Get-Process -Id $p.ProcessId -ErrorAction Stop).Modules)) {
                $fn = [string]$mo.FileName
                if ($fn -match '(?i)\\(Temp|Downloads|Desktop)\\.+\.dll$' -and $fn -notmatch '(?i)lwjgl|jna|jansi|sqlite|zstd|netty|jemalloc|glfw|openal|opengl|freetype|stb|nanovg|vulkan|nvidia|renderdoc') { $tmpMods += $fn }
            }
        } catch {}
        $gd = ''; if ($cmd -match '--gameDir\s+("[^"]+"|\S+)') { $gd = $Matches[1].Trim('"') }
        $started = $p.CreationDate
        $out += [pscustomobject]@{
            PID = $p.ProcessId; Name = $p.Name; Started = (Iso $started); StartedRaw = $started; GameDir = $gd
            CommandLine = $cmd; AgentFlags = @($agent); RiskyFlags = @($risky); AgentFiles = @($agentFiles); TempModules = @($tmpMods | Select-Object -Unique)
            IssueCount = ($agent.Count + $risky.Count + @($tmpMods).Count)
        }
    }
    return $out
}

function Get-LastSessionMods {
    param([string]$ModsDir)
    $res = @{ Ids = @(); Log = ''; When = $null }
    $log = Join-Path (Split-Path -Parent $ModsDir) 'logs\latest.log'
    if (-not (Test-Path -LiteralPath $log)) { return $res }
    $res.Log = $log; $res.When = (Get-Item -LiteralPath $log).LastWriteTime
    $ids = New-Object System.Collections.Generic.List[string]; $inList = $false
    try {
        foreach ($ln in (Get-Content -LiteralPath $log -TotalCount 6000)) {
            if (-not $inList) { if ($ln -match 'Loading \d+ mods?:') { $inList = $true }; continue }
            if ($ln -match '^\s*-\s+(\S+)\s+\S+') { [void]$ids.Add($Matches[1]) }
            elseif ($ln -match '^\s*(\\--|\|--|\|)') { continue }
            else { break }
        }
    } catch {}
    $res.Ids = @($ids | Where-Object { @('minecraft','java','fabricloader','fabric-loader','quilt_loader','mixinextras','forge','neoforge') -notcontains $_ })
    return $res
}

function Find-ModFolders {
    $c = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $ad = $env:APPDATA; $up = $env:USERPROFILE
    $globs = @("$ad\.minecraft\mods", "$ad\PrismLauncher\instances\*\.minecraft\mods", "$ad\PrismLauncher\instances\*\minecraft\mods",
        "$ad\MultiMC\instances\*\.minecraft\mods", "$ad\MultiMC\instances\*\minecraft\mods", "$ad\ModrinthApp\profiles\*\mods",
        "$ad\com.modrinth.theseus\profiles\*\mods", "$ad\gdlauncher_next\instances\*\mods", "$ad\ATLauncher\instances\*\mods",
        "$up\curseforge\minecraft\Instances\*\mods", "$up\Documents\curseforge\minecraft\Instances\*\mods")
    foreach ($j in @(Get-JavaRuntime)) { if ($j.GameDir) { $g = Join-Path $j.GameDir 'mods'; if (Test-Path -LiteralPath $g) { $globs = @($g) + $globs } } }
    foreach ($g in $globs) {
        foreach ($d in @(Get-Item -Path $g -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) {
            if ($seen.ContainsKey($d.FullName.ToLower())) { continue }
            $seen[$d.FullName.ToLower()] = 1
            $n = @(Get-ChildItem -LiteralPath $d.FullName -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.jar(\.disabled)?$' }).Count
            [void]$c.Add([pscustomobject]@{ Path = $d.FullName; Jars = $n })
        }
    }
    return $c
}

function Select-Target {
    Show-Banner
    $cands = @(Find-ModFolders)
    W ''
    W '  Select a mods folder' 'White'
    W ''
    if ($cands.Count -gt 0) {
        for ($i = 0; $i -lt $cands.Count; $i++) {
            WP @( @('  ', 'Gray'), @(('[{0}]' -f ($i + 1)), 'Cyan'), @(('  ' + (Cut $cands[$i].Path ($script:Wd - 22))), 'White'), @(('  {0} jars' -f $cands[$i].Jars), 'DarkGray') )
        }
        W ''
        W '  Type a number, paste a path, or press Enter to use [1].' 'DarkGray'
    } else { W '  No launcher folders found. Paste the path to your mods folder.' 'DarkGray' }
    W ''
    $in = (Read-Host '  PATH').Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($in)) { if ($cands.Count -gt 0) { return $cands[0].Path } return (Join-Path $env:APPDATA '.minecraft\mods') }
    if ($in -match '^\d+$' -and [int]$in -ge 1 -and [int]$in -le $cands.Count) { return $cands[[int]$in - 1].Path }
    return $in
}

# ---------------------------------------------------------------- console result printing
function Print-Mod {
    param($M)
    $col = $script:StCol[$M.Status]
    $extra = ''
    if ($M.Verified -and $M.Modrinth -and $M.Modrinth.Title) { $extra = '= ' + $M.Modrinth.Title + ' ' + $M.Modrinth.Version }
    elseif ($M.Meta -and $M.Meta.Name) { $extra = '~ ' + $M.Meta.Name + ' ' + $M.Meta.Version }
    $glyph = $script:G.dot; $fc = 'White'
    if ($M.Status -eq 'VERIFIED') { $glyph = $script:G.ok; $fc = 'Gray' }
    $fw = [Math]::Max(20, $script:Wd - 43)
    WP @( @('  ', 'Gray'), @(($glyph + ' '), $col), @(('{0,-11} ' -f $M.Status), $col), @(((Cut ([string]$M.RelPath) $fw).PadRight($fw)), $fc), @((' ' + (Cut $extra 22)), 'DarkGray') )
    if ($M.Status -ne 'VERIFIED') {
        $all = @($M.Evidence | Where-Object { $_.Weight -gt 0 })
        $evs = @($all | Select-Object -First 5)
        $more = $all.Count - $evs.Count
        $tagc = @{ critical = 'Red'; high = 'Red'; medium = 'DarkYellow'; low = 'DarkGray' }
        $tags = @{ critical = 'CRIT'; high = 'HIGH'; medium = 'MED '; low = 'LOW ' }
        for ($i = 0; $i -lt $evs.Count; $i++) {
            $e = $evs[$i]
            $conn = $script:G.tee
            if (($i -eq ($evs.Count - 1)) -and ($more -le 0)) { $conn = $script:G.ell }
            WP @( @(('                ' + $conn + ' '), 'DarkGray'), @($tags[$e.Sev], $tagc[$e.Sev]), @((' ' + (Cut ($e.Rule + ' - ' + $e.Detail) ($script:Wd - 28))), 'DarkGray') )
        }
        if ($more -gt 0) { WP @( @(('                ' + $script:G.ell + ' '), 'DarkGray'), @(('+{0} more finding(s) in the HTML report' -f $more), 'DarkGray') ) }
        if ($evs.Count -gt 0) { W '' }
    }
}

# ---------------------------------------------------------------- report helpers
function ConvertTo-SafeJson {
    param($Obj, [int]$Depth = 10, $Warn)
    try {
        $j = ConvertTo-Json -InputObject $Obj -Depth $Depth -Compress -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($j)) { return $j }
    } catch { if ($Warn) { [void]$Warn.Add('JSON: ' + $_.Exception.Message) } }
    return $null
}

function Json-Quote {
    param([string]$S)
    if ($null -eq $S) { return 'null' }
    $t = $S.Replace('\', '\\').Replace('"', '\"')
    $t = [regex]::Replace($t, '[\x00-\x1f]', [Text.RegularExpressions.MatchEvaluator]{ param($m) ('\u{0:x4}' -f [int][char]$m.Value) })
    return ('"' + $t + '"')
}
function ConvertTo-PlainJson {
    param($V, [int]$D = 8)
    if ($null -eq $V) { return 'null' }
    if ($V -is [bool]) { if ($V) { return 'true' } else { return 'false' } }
    if ($V -is [datetime]) { return ('"' + $V.ToString('yyyy-MM-ddTHH:mm:ss') + '"') }
    if ($V -is [byte] -or $V -is [sbyte] -or $V -is [int16] -or $V -is [uint16] -or $V -is [int] -or $V -is [uint32] -or $V -is [long] -or $V -is [uint64]) { return ([string]$V) }
    if ($V -is [double] -or $V -is [single] -or $V -is [decimal]) {
        $dv = [double]$V
        if ([double]::IsNaN($dv) -or [double]::IsInfinity($dv)) { return '0' }
        return $dv.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    if ($V -is [string] -or $V -is [char] -or $V -is [enum] -or $V -is [guid] -or $V -is [uri]) { return (Json-Quote ([string]$V)) }
    if ($D -le 0) { return (Json-Quote ([string]$V)) }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($V -is [System.Collections.IDictionary]) {
        foreach ($k in @($V.Keys)) { [void]$parts.Add((Json-Quote ([string]$k)) + ':' + (ConvertTo-PlainJson $V[$k] ($D - 1))) }
        return ('{' + ($parts -join ',') + '}')
    }
    if ($V -is [System.Collections.IEnumerable]) {
        foreach ($it in $V) { [void]$parts.Add((ConvertTo-PlainJson $it ($D - 1))) }
        return ('[' + ($parts -join ',') + ']')
    }
    foreach ($pr in $V.PSObject.Properties) {
        $val = $null
        try { $val = $pr.Value } catch { $val = $null }
        [void]$parts.Add((Json-Quote ([string]$pr.Name)) + ':' + (ConvertTo-PlainJson $val ($D - 1)))
    }
    return ('{' + ($parts -join ',') + '}')
}
function New-ReportJson {
    param($Report, $Warn)
    $j = ConvertTo-SafeJson $Report 10 $Warn
    if ($j) { return $j }
    [void]$Warn.Add('ConvertTo-Json failed; used built-in JSON writer instead.')
    return (ConvertTo-PlainJson $Report 10)
}
function Get-ReportTemplate {
    $rel = 'templates\report.html'
    $marker = '__ONYX_DATA_B64__'
    if ($PSScriptRoot) {
        $local = Join-Path $PSScriptRoot $rel
        if (Test-Path -LiteralPath $local) { return [IO.File]::ReadAllText($local, [Text.Encoding]::UTF8) }
    }
    $cache = Join-Path $AppDir $rel
    if (-not $Offline -and $RepoRaw -and $RepoRaw -notmatch 'YOUR-USERNAME') {
        try {
            $t = Invoke-RestMethod -Uri ($RepoRaw + '/templates/report.html') -TimeoutSec 20 -UseBasicParsing -ErrorAction Stop
            if (($t -is [string]) -and $t.Contains($marker)) {
                New-Item -ItemType Directory -Force -Path (Split-Path $cache) | Out-Null
                [IO.File]::WriteAllText($cache, $t, (New-Object System.Text.UTF8Encoding($false)))
                return $t
            }
        } catch {}
    }
    if (Test-Path -LiteralPath $cache) { return [IO.File]::ReadAllText($cache, [Text.Encoding]::UTF8) }
    return $null
}

# ---------------------------------------------------------------- main scan
function Invoke-OnyxScan {
    param([string]$Target)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $Target = $Target.Trim().Trim('"').TrimEnd('\')
    if (-not (Test-Path -LiteralPath $Target -PathType Container)) {
        W ''; W ("  [ERROR] Directory not found: " + $Target) 'Red'
        if (-not $NoPrompt) { [void](Read-Host '  Press Enter to exit') }
        return $null
    }
    Show-Banner
    W ''
    WP @( @('  Target  ', 'DarkGray'), @($Target, 'White') )
    WP @( @('  Mode    ', 'DarkGray'), @(('{0}{1}{2}{3}' -f $Depth, $(if ($Recurse) { ', recursive' } else { '' }), $(if ($Offline) { ', offline' } else { '' }), $(if (-not $Native) { ', reduced-accuracy (no native helper)' } else { '' })), 'White') )
    W ''
    $gci = @{ LiteralPath = $Target; File = $true; Force = $true }
    if ($Recurse) { $gci.Recurse = $true }
    $all = @(Get-ChildItem @gci -ErrorAction SilentlyContinue)
    $jars = @($all | Where-Object { $_.Name -match '\.jar(\.disabled)?$' })
    $others = @($all | Where-Object { $_.Name -notmatch '\.jar(\.disabled)?$' })
    WP @( @('  Found   ', 'DarkGray'), @(('{0} JAR file(s), {1} other file(s)' -f $jars.Count, $others.Count), 'Cyan') )
    W ''

    Step 1 'Hashing (SHA-1 + SHA-256)'
    $hashes = @{}; $i = 0
    foreach ($f in $jars) {
        $i++; Show-Bar 'hash' $i $jars.Count $f.Name
        $hashes[$f.FullName] = Get-Hashes $f.FullName
    }
    Clear-Bar

    Step 2 'Modrinth batch verification'
    $mrr = Resolve-Modrinth @($hashes.Values | ForEach-Object { $_.Sha1 })
    $mrState = $mrr.State
    if ($mrState -eq 'offline') { W '        offline mode: nothing verified against Modrinth.' 'DarkYellow' }
    elseif ($mrState -eq 'unreachable') { W '        Modrinth unreachable: UNKNOWN does not mean unsafe here.' 'DarkYellow' }
    elseif ($mrState -eq 'partial') { W '        some lookups failed; results may be incomplete.' 'DarkYellow' }
    else { WP @( @('        ', 'Gray'), @(($script:G.ok + ' '), 'Green'), @(('{0} of {1} file(s) verified' -f $mrr.Map.Count, $jars.Count), 'Green') ) }

    Step 3 ('Deep archive analysis ({0})' -f $Depth)
    $mods = New-Object System.Collections.Generic.List[object]; $i = 0
    foreach ($f in $jars) {
        $i++; Show-Bar 'scan' $i $jars.Count $f.Name
        [void]$mods.Add((Analyze-Mod $f $hashes[$f.FullName] $mrr.Map $Target))
    }
    Clear-Bar

    Step 4 'Folder and cross-file checks'
    $folder = @(Get-FolderIssues $others)
    $cross = New-Object System.Collections.Generic.List[object]
    $byId = @{}
    foreach ($m in $mods) { if ($m.Meta -and $m.Meta.Id -and -not $m.Disabled) { if (-not $byId.ContainsKey($m.Meta.Id)) { $byId[$m.Meta.Id] = @() }; $byId[$m.Meta.Id] += $m.File } }
    foreach ($k in $byId.Keys) {
        if ($byId[$k].Count -gt 1) {
            $grp = @($mods | Where-Object { $_.Meta -and $_.Meta.Id -eq $k -and -not $_.Disabled })
            $nv = @($grp | Where-Object { $_.Verified }).Count
            $sev = 'medium'; $ttl = "Duplicate mod id '$k'"
            if ($nv -gt 0 -and $nv -lt $grp.Count) { $sev = 'high'; $ttl = "Unverified jar reuses the id of a verified mod ('$k')" }
            [void]$cross.Add([pscustomobject]@{ Sev = $sev; Title = $ttl; Detail = ($byId[$k] -join ', ') })
        }
    }
    $bySha = @{}
    foreach ($m in $mods) { if ($m.SHA1) { if (-not $bySha.ContainsKey($m.SHA1)) { $bySha[$m.SHA1] = @() }; $bySha[$m.SHA1] += $m.File } }
    foreach ($k in $bySha.Keys) { if ($bySha[$k].Count -gt 1) { [void]$cross.Add([pscustomobject]@{ Sev = 'low'; Title = 'Identical files'; Detail = ($bySha[$k] -join ', ') }) } }

    Step 5 'Running Minecraft JVM inspection'
    $jvm = @(Get-JavaRuntime)
    $earliest = $null
    foreach ($j in $jvm) { if ($j.StartedRaw -and (($null -eq $earliest) -or $j.StartedRaw -lt $earliest)) { $earliest = $j.StartedRaw } }
    if ($earliest) {
        foreach ($m in $mods) {
            if ($m.Disabled) { continue }
            try {
                if (([datetime]$m.Modified) -gt $earliest.AddSeconds(5)) {
                    $m.Evidence = @($m.Evidence) + @([pscustomobject]@{ Sev = 'high'; Category = 'Timeline'; Rule = 'Modified after game launch'; Detail = "File changed at $($m.Modified), after Minecraft started at $(Iso $earliest). Swapping jars after launch hides them from a scan."; Where = 'structure'; Count = 1; Locations = @(); Weight = 20; Disc = $false })
                    Set-Verdict $m
                }
            } catch {}
        }
    }
    $ls = Get-LastSessionMods $Target
    if ($ls.Ids.Count -gt 0) {
        $have = @{}
        foreach ($m in $mods) { if ($m.Meta -and $m.Meta.Id) { $have[$m.Meta.Id] = 1 }; foreach ($n in $m.NestedModIds) { $have[$n] = 1 } }
        $gone = @($ls.Ids | Where-Object { -not $have.ContainsKey($_) })
        if ($gone.Count -gt 0) {
            [void]$cross.Add([pscustomobject]@{ Sev = 'medium'; Title = 'Mods loaded last session but missing now'; Detail = (($gone | Select-Object -First 15) -join ', ') + $(if ($gone.Count -gt 15) { " (+$($gone.Count - 15) more)" } else { '' }) + "  [from $($ls.Log), written $(Iso $ls.When)]. Removed or renamed since last launch; verify this was intentional." })
        }
    }

    $order = @{ CRITICAL = 0; SUSPICIOUS = 1; REVIEW = 2; OBFUSCATED = 3; UNKNOWN = 4; VERIFIED = 5 }
    $sorted = @($mods | Sort-Object @{ Expression = { $order[$_.Status] } }, @{ Expression = { -$_.Score } }, File)
    $cnt = @{}; foreach ($s in $order.Keys) { $cnt[$s] = @($mods | Where-Object { $_.Status -eq $s }).Count }
    $jvmIssues = @($jvm | Where-Object { $_.IssueCount -gt 0 })
    $folderHigh = @($folder | Where-Object { $_.Sev -eq 'high' }).Count
    $crossMed = @($cross | Where-Object { $_.Sev -eq 'medium' }).Count

    $pen = [Math]::Min(70, $cnt.CRITICAL * 40) + [Math]::Min(40, $cnt.SUSPICIOUS * 15) + [Math]::Min(20, $cnt.REVIEW * 5) + [Math]::Min(10, $cnt.OBFUSCATED * 3) + [Math]::Min(6, $cnt.UNKNOWN) + [Math]::Min(30, $jvmIssues.Count * 15) + [Math]::Min(16, $folderHigh * 8) + [Math]::Min(10, $crossMed * 4)
    $score = [Math]::Max(0, 100 - $pen)
    if ($cnt.CRITICAL -gt 0) { $score = [Math]::Min($score, 49) } elseif ($cnt.SUSPICIOUS -gt 0) { $score = [Math]::Min($score, 74) }
    if ($score -ge 90) { $level = 'LOW'; $grade = 'A' } elseif ($score -ge 75) { $level = 'MODERATE'; $grade = 'B' } elseif ($score -ge 50) { $level = 'HIGH'; $grade = 'C' } elseif ($score -ge 30) { $level = 'CRITICAL'; $grade = 'D' } else { $level = 'CRITICAL'; $grade = 'F' }
    if ($cnt.CRITICAL -gt 0) { $headline = "$($cnt.CRITICAL) file(s) show critical indicators. Do not launch this mod set until they are reviewed." }
    elseif ($cnt.SUSPICIOUS -gt 0) { $headline = "$($cnt.SUSPICIOUS) file(s) are suspicious and need a manual look." }
    elseif ($cnt.REVIEW -gt 0 -or $jvmIssues.Count -gt 0 -or $folderHigh -gt 0) { $headline = 'No strong threat indicators, but some items deserve a quick review.' }
    else { $headline = 'No threat indicators found in this scan.' }

    # ---- reports first (so the result screen can end with their paths) ----
    Step 6 'Writing reports'
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $jsonPath = Join-Path $ReportDir ("Onyx_$ts.json"); $htmlPath = Join-Path $ReportDir ("Onyx_$ts.html")
    $reportWarn = New-Object System.Collections.Generic.List[string]
    try {
        $totalBytes = 0L; foreach ($mm in $mods) { $totalBytes += [long]$mm.SizeBytes }
        $jvmOut = @($jvm | ForEach-Object { $_ | Select-Object PID, Name, Started, GameDir, CommandLine, AgentFlags, RiskyFlags, AgentFiles, TempModules, IssueCount })
        $stage = 'build-report'
        $report = [pscustomobject]@{
            Meta = [pscustomobject]@{
                Engine = 'Onyx Mod Analyzer'; Version = $Version; Timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'); Host = $env:COMPUTERNAME; User = $env:USERNAME
                PowerShell = $PSVersionTable.PSVersion.ToString(); Target = $Target; Depth = $Depth; Recurse = [bool]$Recurse; Offline = [bool]$Offline
                ModrinthState = $mrState; NativeHelper = $Native; DurationSec = [Math]::Round($sw.Elapsed.TotalSeconds, 1); RuleCount = $RuleList.Count
            }
            Summary = [pscustomobject]@{
                Total = $mods.Count; Verified = $cnt.VERIFIED; Unknown = $cnt.UNKNOWN; Obfuscated = $cnt.OBFUSCATED; Review = $cnt.REVIEW
                Suspicious = $cnt.SUSPICIOUS; Critical = $cnt.CRITICAL; JvmIssues = $jvmIssues.Count; FolderIssues = $folder.Count
                TotalBytes = [long]$totalBytes; SecurityScore = $score; Grade = $grade; RiskLevel = $level; Headline = $headline
            }
            Mods = @($sorted); Folder = @($folder); Cross = (ToArr $cross); Jvm = $jvmOut
        }
        $stage = 'json'
        $json = [string](@(New-ReportJson $report $reportWarn) -join '')
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $stage = 'write-json'
        [IO.File]::WriteAllText($jsonPath, $json, $utf8)
        # The data goes into the page as Base64 so no character inside a mod can ever break the HTML/JS.
        $b64 = [Convert]::ToBase64String($utf8.GetBytes($json))
        $stage = 'template'
        $tpl = @(Get-ReportTemplate) -join "`n"
        if (-not [string]::IsNullOrWhiteSpace($tpl) -and $tpl.Contains('__ONYX_DATA_B64__')) {
            $html = ([string]$tpl).Replace('__ONYX_DATA_B64__', [string]$b64)
        } else {
            [void]$reportWarn.Add('report.html template not found - wrote a plain data page instead.')
            $html = '<!doctype html><meta charset="utf-8"><title>Onyx report</title><body style="font-family:Consolas,monospace;background:#0b0d10;color:#e6ebf0"><p>templates\report.html is missing; raw data below.</p><pre style="white-space:pre-wrap;word-break:break-all">' + [Net.WebUtility]::HtmlEncode($json) + '</pre>'
        }
        $stage = 'write-html'
        [IO.File]::WriteAllText($htmlPath, $html, $utf8)
    } catch {
        $ex = $_
        [void]$reportWarn.Add('Report writing failed at stage [' + $stage + ']: ' + $ex.Exception.Message + ' | ' + $ex.Exception.GetType().FullName + ' | line ' + $ex.InvocationInfo.ScriptLineNumber + ': ' + ([string]$ex.InvocationInfo.Line).Trim())
        # Recovery: rebuild the report with the built-in JSON writer and the normal HTML template.
        try {
            $u8 = New-Object System.Text.UTF8Encoding($false)
            $metaR = @{ Engine = 'Onyx Mod Analyzer'; Version = [string]$Version; Timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'); Host = [string]$env:COMPUTERNAME; User = [string]$env:USERNAME; PowerShell = [string]$PSVersionTable.PSVersion; Target = [string]$Target; Depth = [string]$Depth; Recurse = [bool]$Recurse; Offline = [bool]$Offline; ModrinthState = [string]$mrState; NativeHelper = [bool]$Native; DurationSec = [double]$sw.Elapsed.TotalSeconds; RuleCount = 0 }
            $sumR = @{ Total = [int]$mods.Count; Verified = [int]$cnt.VERIFIED; Unknown = [int]$cnt.UNKNOWN; Obfuscated = [int]$cnt.OBFUSCATED; Review = [int]$cnt.REVIEW; Suspicious = [int]$cnt.SUSPICIOUS; Critical = [int]$cnt.CRITICAL; JvmIssues = [int]@($jvmIssues).Count; FolderIssues = [int]@($folder).Count; TotalBytes = 0; SecurityScore = [int]$score; Grade = [string]$grade; RiskLevel = [string]$level; Headline = [string]$headline }
            $tb = 0L; foreach ($mm in (ToArr $mods)) { try { $tb += [long]$mm.SizeBytes } catch {} }
            $sumR.TotalBytes = $tb
            $jvmR = @(); foreach ($jj in @($jvm)) { $jvmR += , ([pscustomobject]@{ PID = [string]$jj.PID; Name = [string]$jj.Name; Started = [string]$jj.Started; GameDir = [string]$jj.GameDir; CommandLine = [string]$jj.CommandLine; AgentFlags = @($jj.AgentFlags); RiskyFlags = @($jj.RiskyFlags); AgentFiles = @($jj.AgentFiles); TempModules = @($jj.TempModules); IssueCount = [int]$jj.IssueCount }) }
            $rep2 = @{ Meta = $metaR; Summary = $sumR; Mods = @($sorted); Folder = @($folder); Cross = (ToArr $cross); Jvm = $jvmR }
            $json2 = ConvertTo-PlainJson $rep2 10
            [IO.File]::WriteAllText($jsonPath, $json2, $u8)
            $tpl2 = @(Get-ReportTemplate) -join "`n"
            if (-not [string]::IsNullOrWhiteSpace($tpl2) -and $tpl2.Contains('__ONYX_DATA_B64__')) {
                $b642 = [Convert]::ToBase64String($u8.GetBytes([string]$json2))
                [IO.File]::WriteAllText($htmlPath, $tpl2.Replace('__ONYX_DATA_B64__', $b642), $u8)
                [void]$reportWarn.Add('Recovered: report written with the built-in JSON writer.')
            } else { throw 'template missing' }
        } catch {
            [void]$reportWarn.Add('Recovery failed too: ' + $_.Exception.Message + ' | line ' + $_.InvocationInfo.ScriptLineNumber)
            try {
                $lines = foreach ($m in $sorted) { ('{0,-11} {1}  ({2} finding(s))' -f $m.Status, $m.File, @($m.Evidence).Count) }
                $txt = "Onyx report (fallback)`n" + ((ToArr $reportWarn) -join "`n") + "`n`n" + (@($lines) -join "`n")
                [IO.File]::WriteAllText($htmlPath, ('<!doctype html><meta charset="utf-8"><title>Onyx report</title><body style="font-family:Consolas,monospace;background:#0b0d10;color:#e6ebf0"><pre style="white-space:pre-wrap">' + [Net.WebUtility]::HtmlEncode($txt) + '</pre>'), (New-Object System.Text.UTF8Encoding($false)))
            } catch {}
        }
    }

    # ---- result screen ----
    Show-Banner
    WP @( @('  Target  ', 'DarkGray'), @($Target, 'White') )
    $sc = 'Red'
    if ($score -ge 90) { $sc = 'Green' } elseif ($score -ge 75) { $sc = 'Yellow' } elseif ($score -ge 50) { $sc = 'DarkYellow' }
    $sb = Bar ($score / 100) 30
    W ''
    Box-Top
    Box-Row @( @(' ', 'Gray'), @('SECURITY SCORE   ', 'DarkGray'), @($sb[0], $sc), @($sb[1], 'DarkGray'), @(('  {0}/100  GRADE {1}' -f $score, $grade), $sc) )
    Box-Row @( @(' ', 'Gray'), @('RISK LEVEL       ', 'DarkGray'), @($level, $sc), @(('   {0} file(s) scanned in {1}s' -f $mods.Count, [Math]::Round($sw.Elapsed.TotalSeconds, 1)), 'DarkGray') )
    Box-Bot
    foreach ($l in (Wrap $headline ($script:Wd - 6))) { W ('  ' + $l) $sc }
    W ''
    foreach ($k in 'CRITICAL', 'SUSPICIOUS', 'REVIEW', 'OBFUSCATED', 'UNKNOWN', 'VERIFIED') {
        $n = [int]$cnt[$k]; $bw = 24; $f = 0
        if ($mods.Count -gt 0 -and $n -gt 0) { $f = [Math]::Max(1, [int][Math]::Round($n / $mods.Count * $bw)) }
        WP @( @('  ', 'Gray'), @(($script:G.dot + ' '), $script:StCol[$k]), @(('{0,-11}' -f $k), $script:StCol[$k]), @(('{0,3}  ' -f $n), 'White'), @((Rep $script:G.full $f), $script:StCol[$k]), @((Rep $script:G.empty ($bw - $f)), 'DarkGray') )
    }
    WP @( @('  ', 'Gray'), @(($script:G.dot + ' '), 'Cyan'), @(('{0,-11}' -f 'JVM'), 'Cyan'), @(('{0,3}  ' -f $jvmIssues.Count), 'White'), @('issue(s)', 'DarkGray'), @('     ', 'Gray'), @(($script:G.dot + ' '), 'Cyan'), @('FOLDER  ', 'Cyan'), @(('{0}  ' -f $folder.Count), 'White'), @('issue(s)', 'DarkGray') )
    W ''
    Rule 'MOD DETAILS'
    W ''
    $okCount = 0
    foreach ($m in $sorted) {
        if ($Compact -and $m.Status -eq 'VERIFIED') { $okCount++; continue }
        Print-Mod $m
    }
    if ($okCount -gt 0) { WP @( @('  ', 'Gray'), @(($script:G.ok + ' '), 'Green'), @(('{0} verified mod(s) hidden (compact mode)' -f $okCount), 'DarkGray') ) }
    if ($folder.Count -gt 0 -or $cross.Count -gt 0 -or $jvm.Count -gt 0) { W ''; Rule 'SYSTEM CHECKS' }
    foreach ($f in $folder) { WP @( @('  ', 'Gray'), @('DIR  ', 'Red'), @(("{0}: {1}" -f $f.Title, (Cut $f.Detail 50)), 'Gray') ) }
    foreach ($x in $cross) { WP @( @('  ', 'Gray'), @('X    ', 'DarkYellow'), @(("{0}: {1}" -f $x.Title, (Cut $x.Detail 60)), 'Gray') ) }
    if ($jvm.Count -eq 0) { WP @( @('  ', 'Gray'), @(($script:G.ok + ' '), 'Green'), @('No Minecraft Java process is running (JVM checks skipped).', 'DarkGray') ) }
    foreach ($j in $jvm) {
        if ($j.IssueCount -gt 0) {
            WP @( @('  ', 'Gray'), @(($script:G.dot + ' '), 'Red'), @(("JVM PID {0}: {1} indicator(s)" -f $j.PID, $j.IssueCount), 'Red') )
            foreach ($f in @($j.AgentFlags) + @($j.RiskyFlags)) { W ("      " + (Cut $f 70)) 'DarkYellow' }
            foreach ($f in $j.TempModules) { W ("      DLL from temp/user folder: " + (Cut $f 50)) 'DarkYellow' }
        } else { WP @( @('  ', 'Gray'), @(($script:G.ok + ' '), 'Green'), @(("JVM PID {0}: no agent or risky flags." -f $j.PID), 'Green') ) }
    }
    W ''
    Rule
    foreach ($w in @($reportWarn | Select-Object -Unique | Select-Object -First 4)) {
        $wl = @(Wrap $w ($script:Wd - 8)); $first = $true
        foreach ($l in $wl) { $lead = '  '; if ($first) { $lead = '! ' }; WP @( @('  ', 'Gray'), @($lead, 'Yellow'), @($l, 'Yellow') ); $first = $false }
    }
    WP @( @('  HTML   ', 'DarkGray'), @($htmlPath, 'Gray') )
    WP @( @('  JSON   ', 'DarkGray'), @($jsonPath, 'Gray') )
    W '  UNKNOWN is not proof of a cheat; findings are indicators, not verdicts.' 'DarkGray'
    return [pscustomobject]@{ Html = $htmlPath; Json = $jsonPath; Critical = $cnt.CRITICAL; Suspicious = $cnt.SUSPICIOUS; Review = $cnt.REVIEW; Dir = $ReportDir }
}

# ---------------------------------------------------------------- entry
$target = $Path
$res = $null
$rescan = $true
while ($rescan) {
    $rescan = $false
    if ([string]::IsNullOrWhiteSpace($target)) {
        if ($NoPrompt) { $target = Join-Path $env:APPDATA '.minecraft\mods' } else { $target = Select-Target }
    }
    $res = Invoke-OnyxScan $target
    if ($null -eq $res) { exit 1 }
    if ($OpenReport -and (Test-Path -LiteralPath $res.Html)) { Start-Process -FilePath $res.Html }
    if ($NoPrompt) { break }
    $menu = $true
    while ($menu) {
        W ''
        WP @( @('  ', 'Gray'), @('[R]', 'Cyan'), @(' Rescan   ', 'Gray'), @('[N]', 'Cyan'), @(' New folder   ', 'Gray'), @('[O]', 'Cyan'), @(' Open report   ', 'Gray'), @('[F]', 'Cyan'), @(' Open folder   ', 'Gray'), @('[Q]', 'Cyan'), @(' Quit', 'Gray') )
        $choice = (Read-Host '  >').Trim()
        if ($choice -match '^[Oo]$') { if (Test-Path -LiteralPath $res.Html) { Start-Process -FilePath $res.Html } else { W '  The HTML report was not written; see the warning above.' 'Yellow' } }
        elseif ($choice -match '^[Ff]$') { Start-Process -FilePath $res.Dir }
        elseif ($choice -match '^[Rr]$') { $rescan = $true; $menu = $false }
        elseif ($choice -match '^[Nn]$') { $target = ''; $rescan = $true; $menu = $false }
        else { $menu = $false }
    }
}
if ($NoPrompt -and $res) {
    if ($res.Critical -gt 0) { exit 3 } elseif ($res.Suspicious -gt 0) { exit 2 } elseif ($res.Review -gt 0) { exit 1 } else { exit 0 }
}
