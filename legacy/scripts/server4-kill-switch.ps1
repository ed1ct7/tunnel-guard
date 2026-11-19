#Requires -RunAsAdministrator
param(
    [ValidateSet('Enable', 'Restore')]
    [string] $Action = 'Enable'
)

$ErrorActionPreference = 'Stop'
$rulePrefix = 'Server4KillSwitch-'
$policyStore = 'localhost'
$tunnel = 'MihomoDeadlockTest'
$dataRoot = Join-Path $env:LOCALAPPDATA 'Codex\Mihomo-Deadlock-Test'
$backup = Join-Path $dataRoot 'firewall-profiles-before-kill-switch.xml'
$log = Join-Path $dataRoot 'firewall-kill-switch.log'
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'

function Write-Status([string] $Message) {
    Add-Content -LiteralPath $log -Value $Message -Encoding UTF8
    Write-Host $Message
}

function Update-ComputerPolicy {
    & gpupdate.exe /Target:Computer /Force /Wait:30 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows could not refresh the computer policy.'
    }
}

function Restore-Policy {
    $originalProfiles = Import-Clixml -LiteralPath $backup
    foreach ($profile in $originalProfiles) {
        Set-NetFirewallProfile -PolicyStore $policyStore -Name $profile.Name `
            -Enabled $profile.Enabled -DefaultOutboundAction $profile.DefaultOutboundAction `
            -AllowLocalFirewallRules $profile.AllowLocalFirewallRules
    }
    $ownedRules = Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction SilentlyContinue |
        Where-Object Name -like "$rulePrefix*"
    foreach ($rule in $ownedRules) {
        Remove-NetFirewallRule -Name $rule.Name -PolicyStore $policyStore
    }
    Update-ComputerPolicy
    Write-Status 'Restored the previous Windows firewall policy.'
}

function Get-PublicIPv4 {
    $address = & $curl -4 --noproxy '*' --connect-timeout 4 --max-time 7 -fsS 'https://api.ipify.org'
    if ($LASTEXITCODE -ne 0 -or $address -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw 'The public IPv4 check did not complete.'
    }
    $address.Trim()
}

try {
    Set-Content -LiteralPath $log -Value "Action: $Action" -Encoding UTF8
    if ($Action -eq 'Restore') {
        Restore-Policy
        exit 0
    }

    $core = Join-Path $dataRoot 'v2rayN-Server4\bin\mihomo\mihomo.exe'
    $programs = [ordered] @{
        Mihomo = $core
        Steam = 'C:\Program Files (x86)\Steam\steam.exe'
        SteamWebHelper = 'C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe'
        SteamService = 'C:\Program Files (x86)\Common Files\Steam\steamservice.exe'
        Deadlock = 'D:\SteamLibrary\steamapps\common\Deadlock\game\bin\win64\deadlock.exe'
    }
    foreach ($program in $programs.Values) {
        if (-not (Test-Path -LiteralPath $program -PathType Leaf)) {
            throw "Expected program is missing: $program"
        }
    }
    $listener = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 18761 -State Listen
    if ((Get-Process -Id $listener.OwningProcess).Path -ne $core) {
        throw 'The Server 4 Mihomo process is not listening.'
    }
    if ((Get-NetAdapter -Name $tunnel).Status -ne 'Up') {
        throw 'The Server 4 tunnel adapter is down.'
    }
    Write-Status 'The Server 4 tunnel adapter is up.'
    $expectedIP = (Get-Content -LiteralPath (Join-Path $dataRoot 'amnezia-public-baseline') -Raw).Trim()
    if ((Get-PublicIPv4) -ne $expectedIP) {
        throw 'Current egress does not match the saved Server 4 IPv4.'
    }

    $oldRules = @(Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction SilentlyContinue |
        Where-Object Direction -eq 'Outbound')
    if ($oldRules.Count -ne 0) {
        throw 'Local Group Policy already contains outbound rules. No changes were applied.'
    }
    Get-NetFirewallProfile -PolicyStore $policyStore |
        Select-Object Name,Enabled,DefaultOutboundAction,AllowLocalFirewallRules |
        Export-Clixml -LiteralPath $backup

    $permit = @{
        PolicyStore = $policyStore
        Group = 'Server 4 kill switch'
        Direction = 'Outbound'
        Action = 'Allow'
        Profile = 'Any'
    }
    $ethernet = Get-NetRoute -AddressFamily IPv4 -InterfaceAlias Ethernet -DestinationPrefix '0.0.0.0/0' |
        Sort-Object RouteMetric | Select-Object -First 1
    $probe = '9.9.9.9'
    $probePrefix = "$probe/32"
    $applied = $false
    $hostRoute = $null
    try {
        if (Get-NetRoute -DestinationPrefix $probePrefix -ErrorAction SilentlyContinue) {
            throw 'The neutral test address already has a dedicated route.'
        }
        $hostRoute = New-NetRoute -DestinationPrefix $probePrefix -InterfaceIndex $ethernet.InterfaceIndex `
            -NextHop $ethernet.NextHop -PolicyStore ActiveStore
        $reachable = Test-NetConnection -ComputerName $probe -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if (-not $reachable) {
            throw 'The neutral probe could not reach TCP 443 over Ethernet before the change.'
        }

        $applied = $true
        New-NetFirewallRule @permit -Name "${rulePrefix}Tunnel" -DisplayName 'Server 4 - tunnel' `
            -InterfaceAlias $tunnel | Out-Null
        foreach ($item in $programs.GetEnumerator()) {
            New-NetFirewallRule @permit -Name "$rulePrefix$($item.Key)" `
                -DisplayName "Server 4 - $($item.Key)" -Program $item.Value | Out-Null
        }
        New-NetFirewallRule @permit -Name "${rulePrefix}Dhcp4" -DisplayName 'Server 4 - IPv4 DHCP' `
            -Service Dhcp -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
        Set-NetFirewallProfile -PolicyStore $policyStore -All -Enabled True `
            -DefaultOutboundAction Block -AllowLocalFirewallRules False
        Update-ComputerPolicy

        $activeProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
        if ($activeProfiles.Count -ne 3 -or ($activeProfiles | Where-Object {
            $_.Enabled -ne 'True' -or $_.DefaultOutboundAction -ne 'Block' -or
            $_.AllowLocalFirewallRules -ne 'False'
        })) {
            throw 'The effective firewall profiles do not show the expected outbound lock.'
        }
        if ((Get-PublicIPv4) -ne $expectedIP) {
            throw 'Normal internet traffic did not keep the Server 4 IPv4.'
        }
        Write-Status 'Ordinary HTTPS still exits through Server 4.'

        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $connect = $client.ConnectAsync($probe, 443)
            try {
                $connected = $connect.Wait(4000) -and $client.Connected
            } catch [System.AggregateException] {
                $connected = $false
            }
            if ($connected) {
                throw 'The direct path over Ethernet is still open.'
            }
        } finally {
            $client.Dispose()
        }
        Write-Status 'The same direct Ethernet path is blocked.'
        Write-Status 'Firewall kill switch enabled.'
    } catch {
        if ($applied) {
            Restore-Policy
        }
        throw
    } finally {
        if ($hostRoute) {
            $hostRoute | Remove-NetRoute -Confirm:$false
        }
    }
} catch {
    Write-Status ("ERROR: " + $_.Exception.Message)
    Write-Status $_.ScriptStackTrace
    exit 1
}
