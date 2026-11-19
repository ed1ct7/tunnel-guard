param(
    [Parameter(Mandatory)]
    [ValidateSet('Status','Rules','Targets','Preflight','Enable','Disable','CleanLegacy')]
    [string] $Action,
    [string] $SettingsPath
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$store = 'localhost'
$owned = @('TunnelGuard-Tunnel','TunnelGuard-Mihomo','TunnelGuard-Dhcp')
$legacy = @('Server4KillSwitch-Tunnel','Server4KillSwitch-Mihomo','Server4KillSwitch-Steam',
    'Server4KillSwitch-SteamService','Server4KillSwitch-SteamWebHelper','Server4KillSwitch-Deadlock',
    'Server4KillSwitch-Dhcp4')
$backup = Join-Path (Split-Path -Parent $SettingsPath) 'original-policy.xml'
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'

function Get-GuardState {
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore)
    $ours = @($rules | Where-Object Name -in $owned)
    $old = @($rules | Where-Object Name -in $legacy)
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $blocked = @($profiles | Where-Object { $_.Enabled -eq 'True' -and
        $_.DefaultOutboundAction -eq 'Block' -and $_.AllowLocalFirewallRules -eq 'False' })
    if ($blocked.Count -eq 3 -and @($ours | Where-Object {
        $_.Enabled -eq 'True' -and 'Enforced' -in $_.EnforcementStatus
    }).Count -eq $owned.Count) { return 'On' }
    if ($ours.Count -gt 0 -or (Test-Path -LiteralPath $backup)) { return 'Partial' }
    if ($old.Count -gt 0) {
        if ($blocked.Count -eq 0 -and -not ($profiles | Where-Object DefaultOutboundAction -eq 'Block')) {
            return 'LegacyInactive'
        }
        return 'LegacyActive'
    }
    'Off'
}

function Refresh-Policy {
    & gpupdate.exe /Target:Computer /Force /Wait:30 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to apply Windows policy (gpupdate).' }
}

function Remove-GuardRules([string[]] $Names) {
    $policyRules = @(Get-NetFirewallRule -PolicyStore $store -ErrorAction SilentlyContinue)
    foreach ($rule in ($policyRules | Where-Object Name -in $Names)) {
        Remove-NetFirewallRule -PolicyStore $store -Name $rule.Name
    }
}

function Restore-Guard {
    if (-not (Test-Path -LiteralPath $backup)) { throw 'The backup of the previous policy is missing.' }
    $saved = @(Import-Clixml -LiteralPath $backup)
    if ($saved.Count -ne 3) { throw 'The firewall backup is incomplete.' }
    foreach ($item in $saved) {
        Set-NetFirewallProfile -PolicyStore $store -Name $item.Name -Enabled $item.Enabled `
            -DefaultOutboundAction $item.DefaultOutboundAction -AllowLocalFirewallRules $item.AllowLocalFirewallRules
    }
    Remove-GuardRules $owned
    Refresh-Policy
    if (Get-NetFirewallRule -PolicyStore ActiveStore -Name 'TunnelGuard-*' -ErrorAction SilentlyContinue) {
        throw 'Some guard rules are still active. The backup was kept.'
    }
    Remove-Item -LiteralPath $backup
}

function Test-Tcp([string] $Address) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        try {
            $client.ConnectAsync($Address,443).Wait(3500) -and $client.Connected
        } catch [AggregateException] {
            $false
        }
    } finally {
        $client.Dispose()
    }
}

function Get-ProbeIP([string] $Proxy) {
    $options = if ($Proxy) { @('--noproxy','invalid.invalid','--proxy',$Proxy) } else { @('--noproxy','*') }
    $value = & $curl @options -4 --connect-timeout 4 --max-time 8 -fsS 'https://api.ipify.org'
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw 'The HTTPS verification did not complete.'
    }
    $value.Trim()
}

$stage = 'STATE'

function Read-ConnectionSettings {
    $settings = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $client = [string]$settings.client_path
    $tunnel = [string]$settings.adapter
    $port = [int]$settings.proxy_port
    if (-not [IO.File]::Exists($client) -or -not $tunnel -or $port -lt 1 -or $port -gt 65529) {
        throw 'The v2rayN connection settings are incomplete.'
    }
    $core = Join-Path (Split-Path -Parent $client) 'bin\mihomo\mihomo.exe'
    if (-not [IO.File]::Exists($core)) { throw 'Mihomo was not found in the selected v2rayN folder.' }
    [pscustomobject]@{core=$core;tunnel=$tunnel;port=$port}
}

function Assert-TunReady($connection, [bool] $verifyCore) {
    $tunnel = $connection.tunnel
    $port = $connection.port
    $adapter = Get-NetAdapter -Name $tunnel -ErrorAction SilentlyContinue
    if ($adapter.Status -ne 'Up') { throw 'The selected TUN interface is not up.' }
    $proxy = @(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    $controller = @(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort ($port+6) -State Listen -ErrorAction SilentlyContinue)
    if ($proxy.Count -ne 1 -or $controller.Count -ne 1 -or $proxy[0].OwningProcess -ne $controller[0].OwningProcess) {
        throw 'The selected Mihomo proxy and TUN controller are not both ready.'
    }
    if ($verifyCore -and (Get-Process -Id $proxy[0].OwningProcess -ErrorAction SilentlyContinue).Path -ne $connection.core) {
        throw 'The loopback proxy does not belong to the selected Mihomo installation.'
    }
    $runtime = Invoke-RestMethod -Uri "http://127.0.0.1:$($port+6)/configs" -TimeoutSec 3
    if ($runtime.mode -ne 'rule' -or -not $runtime.tun.enable -or $runtime.tun.device -ne $tunnel) {
        throw 'The selected Mihomo TUN must be up and in Rule mode.'
    }
}

try {
    if ($Action -in @('Rules','Targets')) {
        $options = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $port = [int] $options.proxy_port
        if ($port -lt 1 -or $port -gt 65529) { throw 'Invalid proxy port.' }
        $proxyOwner = (Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $port -State Listen).OwningProcess
        $controller = @(
            Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort ($port+6),($port+5) -State Listen -ErrorAction SilentlyContinue |
                Where-Object OwningProcess -eq $proxyOwner
        )
        if ($controller.Count -ne 1) { throw 'The local Mihomo controller is not available.' }
        $endpoint = if ($Action -eq 'Targets') { 'proxies' } else { 'rules' }
        $raw = & $curl --noproxy '*' --max-time 4 -fsS "http://127.0.0.1:$($controller[0].LocalPort)/$endpoint"
        if ($LASTEXITCODE -ne 0) { throw 'Could not read the local Mihomo controller.' }
        $response = $raw | ConvertFrom-Json
        if ($Action -eq 'Targets') {
            $reserved = @('Direct','Compatible','Pass','PassRule','Reject','RejectDrop','Dns',
                'Selector','URLTest','Fallback','LoadBalance','Relay','Smart')
            $names = @($response.proxies.PSObject.Properties | Where-Object {
                $_.Name -ne 'GLOBAL' -and $_.Value.type -notin $reserved
            } | Select-Object -ExpandProperty Name | Sort-Object)
            @{targets=$names} | ConvertTo-Json -Compress
        } else {
            [pscustomobject] @{rules=@($response.rules | Select-Object type,payload,proxy)} | ConvertTo-Json -Depth 4 -Compress
        }
        exit 0
    }
    if ($Action -eq 'Preflight') {
        $stage = 'SETTINGS'
        $connection = Read-ConnectionSettings
        $stage = 'TUN'
        Assert-TunReady $connection $false
        exit 0
    }
    $state = Get-GuardState
    if ($Action -eq 'Status') {
        $isUp = $false
        if (Test-Path -LiteralPath $SettingsPath) {
            $statusSettings = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $activeAdapter = Get-NetAdapter -Name $statusSettings.Adapter -ErrorAction SilentlyContinue
            $isUp = $activeAdapter.Status -eq 'Up'
        }
        @{state=$state;adapter_up=[bool]$isUp} | ConvertTo-Json -Compress
        exit 0
    }
    $stage = 'ADMIN'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights required.' }

    $stage = 'POLICY'
    if ($Action -eq 'CleanLegacy' -or $state -eq 'LegacyInactive') {
        if ($state -ne 'LegacyInactive') { throw 'Legacy cleanup requires the old protection to be off.' }
        Remove-GuardRules $legacy
        Refresh-Policy
        $state = Get-GuardState
        if ($state -ne 'Off') { throw 'Some previous rules remain active.' }
    }
    if ($Action -eq 'CleanLegacy') { exit 0 }
    if ($Action -eq 'Disable') {
        if ($state -eq 'Off') { exit 0 }
        $stage = 'RESTORE'
        Restore-Guard
        exit 0
    }
    if ($state -eq 'On') { exit 0 }
    $stage = 'RESTORE'
    if ($state -ne 'Off') { throw 'Restore the previous firewall policy first.' }

    $stage = 'SETTINGS'
    $connection = Read-ConnectionSettings
    $stage = 'TUN'
    Assert-TunReady $connection $true
    $tunnel = $connection.tunnel
    $core = $connection.core
    $port = $connection.port
    $stage = 'VERIFY'
    $probe = '9.9.9.9'
    $normalRoute = Find-NetRoute -RemoteIPAddress $probe | Where-Object DestinationPrefix | Select-Object -Last 1
    if ($normalRoute.InterfaceAlias -ne $tunnel) { throw 'Normal traffic does not select the TUN adapter.' }
    $gateway = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Where-Object { $_.InterfaceAlias -ne $tunnel -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric } |
        Select-Object -First 1
    if (-not $gateway) { throw 'No physical IPv4 route was found for the fail-closed test.' }

    $proxy = "http://127.0.0.1:$port"
    $expected = Get-ProbeIP $proxy
    if ((Get-ProbeIP) -ne $expected) { throw 'Windows and the selected VPN proxy use different egress addresses.' }
    $stage = 'CONFLICT'
    if (Get-NetFirewallRule -PolicyStore $store -ErrorAction SilentlyContinue | Where-Object Direction -eq 'Outbound') {
        throw 'Local Group Policy already has outbound rules. They were left intact.'
    }
    $stage = 'VERIFY'
    if (Get-NetRoute -DestinationPrefix "$probe/32" -ErrorAction SilentlyContinue) {
        throw 'The verification address already has a host route.'
    }
    $stage = 'POLICY'
    $saved = Get-NetFirewallProfile -PolicyStore $store |
        Select-Object Name,Enabled,DefaultOutboundAction,AllowLocalFirewallRules
    $hostRoute = $null
    $started = $false
    try {
        $stage = 'VERIFY'
        $hostRoute = New-NetRoute -DestinationPrefix "$probe/32" -InterfaceIndex $gateway.InterfaceIndex `
            -NextHop $gateway.NextHop -PolicyStore ActiveStore
        if (-not (Test-Tcp $probe)) { throw 'The direct verification endpoint is unavailable before applying protection.' }
        $stage = 'POLICY'
        $saved | Export-Clixml -LiteralPath $backup
        $started = $true
        $allow = @{PolicyStore=$store;Group='Tunnel Guard';Direction='Outbound';Action='Allow';Profile='Any'}
        New-NetFirewallRule @allow -Name $owned[0] -DisplayName 'Tunnel Guard - tunnel' -InterfaceAlias $tunnel | Out-Null
        New-NetFirewallRule @allow -Name $owned[1] -DisplayName 'Tunnel Guard - Mihomo' -Program $core | Out-Null
        New-NetFirewallRule @allow -Name $owned[2] -DisplayName 'Tunnel Guard - DHCP' `
            -Service Dhcp -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
        Set-NetFirewallProfile -PolicyStore $store -All -Enabled True `
            -DefaultOutboundAction Block -AllowLocalFirewallRules False
        Refresh-Policy
        if ((Get-GuardState) -ne 'On') { throw 'Windows did not enforce the expected firewall policy.' }
        $stage = 'VERIFY'
        if ((Get-ProbeIP) -ne $expected) { throw 'VPN connectivity was lost after applying protection.' }
        if (Test-Tcp $probe) { throw 'The direct verification route was still reachable.' }
    } catch {
        if ($started) {
            $failedStage = $stage
            $stage = 'RESTORE'
            Restore-Guard
            $stage = $failedStage
        }
        throw
    } finally {
        if ($hostRoute) { $hostRoute | Remove-NetRoute -Confirm:$false }
    }
    Write-Output 'Verified: VPN HTTPS succeeds, direct IPv4 is blocked.'
} catch {
    if ($Action -in @('Preflight','Enable','Disable','CleanLegacy')) {
        [Console]::Error.WriteLine("TG_STAGE:$stage")
    }
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
