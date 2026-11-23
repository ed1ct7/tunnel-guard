param(
    [Parameter(Mandatory)]
    [ValidateSet('Status','Rules','Targets','Diagnose','Preflight','Enable','Disable','CleanLegacy','WfpEnable','WfpUpgrade','WfpDisable')]
    [string] $Action,
    [string] $SettingsPath,
    # %ProgramData%\TunnelGuard: only Administrators and SYSTEM write here.
    [string] $StatePath,
    [string] $ProgressPath
)

# The script runs elevated: load modules only from the Windows directory,
# never from a module path the unelevated user can write to.
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$store = 'localhost'
$owned = @('TunnelGuard-Tunnel','TunnelGuard-Mihomo','TunnelGuard-Dhcp')
$legacy = @('Server4KillSwitch-Tunnel','Server4KillSwitch-Mihomo','Server4KillSwitch-Steam',
    'Server4KillSwitch-SteamService','Server4KillSwitch-SteamWebHelper','Server4KillSwitch-Deadlock',
    'Server4KillSwitch-Dhcp4')
$backup = Join-Path $StatePath 'original-policy.xml'
# Versions up to 0.6.0-preview.4 kept the backup in the user's folder, where
# any unelevated program can edit it. It is only read, validated and never
# deleted from the elevated side.
$legacyBackup = Join-Path (Split-Path -Parent $SettingsPath) 'original-policy.xml'
$curl = Join-Path ([Environment]::SystemDirectory) 'curl.exe'

$progressAction = @{Enable='enable';Disable='disable';CleanLegacy='clean_legacy';WfpEnable='enable';WfpUpgrade='enable';WfpDisable='disable'}[$Action]

# Reports a stage to the panel. Best effort: any failure is swallowed, writes
# nothing to the pipeline and touches no script variable, so it can never
# change the outcome of the operation.
function Set-GuardProgress([string] $ProgressStage) {
    if (-not $ProgressPath -or -not $progressAction) { return }
    try {
        $progressAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $progressJson = @{action=$progressAction;stage=$ProgressStage;at=$progressAt} | ConvertTo-Json -Compress
        $progressTemp = "$ProgressPath.tmp"
        [IO.File]::WriteAllText($progressTemp, $progressJson, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $progressTemp -Destination $ProgressPath -Force
    } catch { }
}

function Get-GuardState {
    # Every owned name starts with 'TunnelGuard-' and every legacy name with
    # 'Server4KillSwitch-', so this name query returns a superset of the rules
    # the exact filters below keep (wildcard name match is case-insensitive,
    # like -in). Errors stay terminating, as with the full listing.
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'TunnelGuard-*','Server4KillSwitch-*')
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

# The saved profile values, checked. From the user-writable legacy backup a
# switched-off firewall is not restored: that file may have been edited.
function Read-PolicyBackup {
    $legacy = -not (Test-Path -LiteralPath $backup)
    $path = if ($legacy) { $legacyBackup } else { $backup }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'The backup of the previous policy is missing.' }
    $saved = @(Import-Clixml -LiteralPath $path)
    $names = @($saved | ForEach-Object { [string] $_.Name } | Sort-Object -Unique)
    if ($saved.Count -ne 3 -or ($names -join ',') -ne 'Domain,Private,Public') {
        throw 'The firewall backup is incomplete.'
    }
    foreach ($item in $saved) {
        $enabled = [string] $item.Enabled
        $outbound = [string] $item.DefaultOutboundAction
        $local = [string] $item.AllowLocalFirewallRules
        if ($enabled -notin @('True','False','NotConfigured') -or
            $outbound -notin @('Allow','Block','NotConfigured') -or
            $local -notin @('True','False','NotConfigured')) {
            throw 'The firewall backup is invalid.'
        }
        if ($legacy -and $enabled -eq 'False') { $enabled = 'NotConfigured' }
        [pscustomobject] @{Name=[string] $item.Name;Enabled=$enabled;DefaultOutboundAction=$outbound;AllowLocalFirewallRules=$local}
    }
}

function Restore-Guard {
    $saved = @(Read-PolicyBackup)
    foreach ($item in $saved) {
        Set-NetFirewallProfile -PolicyStore $store -Name $item.Name -Enabled $item.Enabled `
            -DefaultOutboundAction $item.DefaultOutboundAction -AllowLocalFirewallRules $item.AllowLocalFirewallRules
    }
    Remove-GuardRules $owned
    Refresh-Policy
    if (Get-NetFirewallRule -PolicyStore ActiveStore -Name 'TunnelGuard-*' -ErrorAction SilentlyContinue) {
        throw 'Some guard rules are still active. The backup was kept.'
    }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup }
}

function Invoke-WfpWorker([string] $Operation) {
    $worker = Start-Process -FilePath $env:TUNNEL_GUARD_WFP_WORKER -ArgumentList @('--wfp-worker',$Operation) `
        -WindowStyle Hidden -Wait -PassThru
    if ($worker.ExitCode -ne 0) { throw "Tunnel Guard WFP operation $Operation failed." }
}

function Find-PhysicalGateway([string] $Family, [string] $Tunnel) {
    $default, $unspecified = if ($Family -eq 'IPv4') { '0.0.0.0/0','0.0.0.0' } else { '::/0','::' }
    Get-NetRoute -AddressFamily $Family -DestinationPrefix $default -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -ne $Tunnel -and $_.NextHop -ne $unspecified } |
        Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily $Family).InterfaceMetric } |
        Select-Object -First 1
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

function Get-ProbeIP([string] $Url, [string] $Proxy) {
    $options = if ($Proxy) { @('--noproxy','invalid.invalid','--proxy',$Proxy) } else { @('--noproxy','*') }
    # -q must come first: it stops curl from reading a _curlrc the unelevated
    # user controls (extra output files, proxies, resolve overrides).
    $value = & $curl -q @options --proto '=https' --max-filesize 64 -4 --connect-timeout 4 --max-time 8 -fsS $Url 2>$null
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw 'The HTTPS verification did not complete.'
    }
    $value.Trim()
}

function Get-VerifiedEgress([string] $Proxy) {
    foreach ($url in @('https://api.ipify.org', 'https://ipv4.icanhazip.com')) {
        try {
            $expected = Get-ProbeIP $url $Proxy
            $actual = Get-ProbeIP $url
        } catch {
            continue
        }
        if ($actual -ne $expected) { throw 'Windows and the selected VPN proxy use different egress addresses.' }
        return [pscustomobject]@{url=$url;ip=$expected}
    }
    throw 'The HTTPS verification did not complete through both TUN and the local proxy.'
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

function Find-LocalController([int] $Port, [int[]] $FallbackPorts) {
    $proxy = @(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if ($proxy.Count -ne 1) { throw 'The local Mihomo proxy is not available.' }
    $ports = if ($env:TUNNEL_GUARD_CONTROLLER_PORT) { [int] $env:TUNNEL_GUARD_CONTROLLER_PORT } else { $FallbackPorts }
    $controller = @(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $ports -State Listen -ErrorAction SilentlyContinue |
        Where-Object OwningProcess -eq $proxy[0].OwningProcess)
    if ($controller.Count -ne 1) { throw 'The local Mihomo controller is not available.' }
    $controller[0]
}

function Read-LocalController([int] $Port, [string] $Endpoint) {
    $request = [Net.WebRequest]::CreateHttp("http://127.0.0.1:$Port/$Endpoint")
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.Timeout = 3000
    $request.ReadWriteTimeout = 3000
    $response = $null
    $reader = $null
    try {
        if ($env:TUNNEL_GUARD_CONTROLLER_SECRET) {
            $request.Headers['Authorization'] = "Bearer $env:TUNNEL_GUARD_CONTROLLER_SECRET"
        }
        $response = $request.GetResponse()
        if ($response.StatusCode -ne [Net.HttpStatusCode]::OK) { throw 'Unexpected controller response.' }
        $reader = [IO.StreamReader]::new($response.GetResponseStream(), [Text.Encoding]::UTF8)
        $reader.ReadToEnd() | ConvertFrom-Json
    } catch {
        throw 'Could not read the local Mihomo controller. Check the generated config and controller key.'
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($response) { $response.Dispose() }
    }
}

function Assert-TunReady($connection, [bool] $verifyCore) {
    $tunnel = $connection.tunnel
    $port = $connection.port
    $adapter = Get-NetAdapter -Name $tunnel -ErrorAction SilentlyContinue
    if ($adapter.Status -ne 'Up') { throw 'The selected TUN interface is not up.' }
    $controller = Find-LocalController $port @($port+6)
    if ($verifyCore -and (Get-Process -Id $controller.OwningProcess -ErrorAction SilentlyContinue).Path -ne $connection.core) {
        throw 'The loopback proxy does not belong to the selected Mihomo installation.'
    }
    $runtime = Read-LocalController $controller.LocalPort 'configs'
    if ($runtime.mode -ne 'rule' -or -not $runtime.tun.enable -or $runtime.tun.device -ne $tunnel) {
        throw 'The selected Mihomo TUN must be up and in Rule mode.'
    }
    [int] $controller.OwningProcess
}

try {
    if ($Action -in @('Rules','Targets')) {
        $options = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $port = [int] $options.proxy_port
        if ($port -lt 1 -or $port -gt 65529) { throw 'Invalid proxy port.' }
        $controller = Find-LocalController $port (($port+6),($port+5))
        $endpoint = if ($Action -eq 'Targets') { 'proxies' } else { 'rules' }
        $response = Read-LocalController $controller.LocalPort $endpoint
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
    if ($Action -eq 'Diagnose') {
        # Read-only facts for the panel's diagnosis; needs no administrator rights.
        $diagAdapter = [string] $env:TUNNEL_GUARD_DIAG_ADAPTER
        $diagPort = [int] $env:TUNNEL_GUARD_DIAG_PORT
        $diagControllerPort = [int] $env:TUNNEL_GUARD_DIAG_CONTROLLER
        $diagNic = $null
        if ($diagAdapter) { $diagNic = Get-NetAdapter -Name $diagAdapter -ErrorAction SilentlyContinue | Select-Object -First 1 }
        $diagLoopback = @('127.0.0.1', '0.0.0.0', '::', '::1')
        $diagProxy = @()
        $diagController = @()
        if ($diagPort -ge 1 -and $diagPort -le 65535) {
            $diagProxy = @(Get-NetTCPConnection -LocalPort $diagPort -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalAddress -in $diagLoopback } |
                ForEach-Object { [int] $_.OwningProcess } | Sort-Object -Unique)
        }
        if ($diagControllerPort -ge 1 -and $diagControllerPort -le 65535) {
            $diagController = @(Get-NetTCPConnection -LocalPort $diagControllerPort -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalAddress -in $diagLoopback } |
                ForEach-Object { [int] $_.OwningProcess } | Sort-Object -Unique)
        }
        [pscustomobject] @{
            adapter_exists = [bool] $diagNic
            adapter_status = if ($diagNic) { [string] $diagNic.Status } else { $null }
            client_running = @(Get-Process -Name v2rayN -ErrorAction SilentlyContinue).Count -gt 0
            proxy_pids = [int[]] $diagProxy
            controller_pids = [int[]] $diagController
        } | ConvertTo-Json -Compress
        exit 0
    }
    if ($Action -eq 'Preflight') {
        $stage = 'SETTINGS'
        $connection = Read-ConnectionSettings
        $stage = 'TUN'
        $null = Assert-TunReady $connection $false
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

    if ($Action -eq 'WfpDisable') {
        $stage = 'RESTORE'
        Set-GuardProgress 'restore'
        if ($state -notin @('Off','LegacyInactive')) { Restore-Guard }
        Invoke-WfpWorker 'Remove'
        exit 0
    }

    $wfp = $Action -in @('WfpEnable','WfpUpgrade')
    # Replaces an active older filter set; the direct path is already blocked.
    $upgrade = $Action -eq 'WfpUpgrade'
    $stage = 'POLICY'
    if ($Action -eq 'CleanLegacy' -or ($state -eq 'LegacyInactive' -and -not $wfp)) {
        if ($state -ne 'LegacyInactive') { throw 'Legacy cleanup requires the old protection to be off.' }
        Set-GuardProgress 'cleanup'
        Remove-GuardRules $legacy
        Set-GuardProgress 'policy'
        Refresh-Policy
        $state = Get-GuardState
        if ($state -ne 'Off') { throw 'Some previous rules remain active.' }
    }
    if ($Action -eq 'CleanLegacy') { exit 0 }
    if ($Action -eq 'Disable') {
        if ($state -eq 'Off') { exit 0 }
        $stage = 'RESTORE'
        Set-GuardProgress 'restore'
        Restore-Guard
        exit 0
    }
    if ($state -eq 'On' -and -not $wfp) { exit 0 }
    $stage = 'RESTORE'
    if ($state -ne 'Off' -and -not ($wfp -and $state -eq 'LegacyInactive')) {
        throw 'Restore the previous firewall policy first.'
    }

    $stage = 'SETTINGS'
    Set-GuardProgress 'settings'
    $connection = Read-ConnectionSettings
    $stage = 'TUN'
    Set-GuardProgress 'tun'
    $corePid = Assert-TunReady $connection $true
    $tunnel = $connection.tunnel
    $core = $connection.core
    $port = $connection.port
    # The WFP worker uses exactly what was checked here, not a fresh read of
    # the user-writable settings file.
    $env:TUNNEL_GUARD_WFP_CORE = $core
    $env:TUNNEL_GUARD_WFP_ADAPTER = $tunnel
    $env:TUNNEL_GUARD_WFP_CORE_PID = [string] $corePid
    $stage = 'VERIFY'
    $probe = '9.9.9.9'
    $normalRoute = Find-NetRoute -RemoteIPAddress $probe | Where-Object DestinationPrefix | Select-Object -Last 1
    if ($normalRoute.InterfaceAlias -ne $tunnel) { throw 'Normal traffic does not select the TUN adapter.' }
    $gateway = Find-PhysicalGateway 'IPv4' $tunnel
    if (-not $gateway) { throw 'No physical IPv4 route was found for the fail-closed test.' }
    $probes = @([pscustomobject] @{address=$probe;prefix="$probe/32";gateway=$gateway})
    if ($wfp) {
        $gateway6 = Find-PhysicalGateway 'IPv6' $tunnel
        if ($gateway6) {
            $probes += [pscustomobject] @{address='2620:fe::fe';prefix='2620:fe::fe/128';gateway=$gateway6}
        }
    }

    $proxy = "http://127.0.0.1:$port"
    Set-GuardProgress 'egress'
    $egress = Get-VerifiedEgress $proxy
    $stage = 'CONFLICT'
    if (-not $wfp -and (Get-NetFirewallRule -PolicyStore $store -ErrorAction SilentlyContinue | Where-Object Direction -eq 'Outbound')) {
        throw 'Local Group Policy already has outbound rules. They were left intact.'
    }
    $stage = 'VERIFY'
    $hostRoutes = @()
    $started = $false
    $upgraded = $false
    try {
        foreach ($route in $probes) {
            if (Get-NetRoute -DestinationPrefix $route.prefix -ErrorAction SilentlyContinue) {
                throw 'The verification address already has a host route.'
            }
            $hostRoutes += New-NetRoute -DestinationPrefix $route.prefix -InterfaceIndex $route.gateway.InterfaceIndex `
                -NextHop $route.gateway.NextHop -PolicyStore ActiveStore
            if (-not $upgrade -and -not (Test-Tcp $route.address)) {
                throw 'A direct verification endpoint is unavailable before applying protection.'
            }
        }
        if ($wfp) {
            $stage = 'WFP'
            Set-GuardProgress 'apply'
            $started = $true
            Invoke-WfpWorker $(if ($upgrade) { 'Upgrade' } else { 'Apply' })
            $upgraded = $upgrade
        } else {
            $stage = 'POLICY'
            Set-GuardProgress 'backup'
            Get-NetFirewallProfile -PolicyStore $store |
                Select-Object Name,Enabled,DefaultOutboundAction,AllowLocalFirewallRules |
                Export-Clixml -LiteralPath $backup
            $started = $true
            Set-GuardProgress 'apply'
            $allow = @{PolicyStore=$store;Group='Tunnel Guard';Direction='Outbound';Action='Allow';Profile='Any'}
            New-NetFirewallRule @allow -Name $owned[0] -DisplayName 'Tunnel Guard - tunnel' -InterfaceAlias $tunnel | Out-Null
            New-NetFirewallRule @allow -Name $owned[1] -DisplayName 'Tunnel Guard - Mihomo' -Program $core | Out-Null
            New-NetFirewallRule @allow -Name $owned[2] -DisplayName 'Tunnel Guard - DHCP' `
                -Service Dhcp -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
            Set-NetFirewallProfile -PolicyStore $store -All -Enabled True `
                -DefaultOutboundAction Block -AllowLocalFirewallRules False
            Set-GuardProgress 'policy'
            Refresh-Policy
            if ((Get-GuardState) -ne 'On') { throw 'Windows did not enforce the expected firewall policy.' }
        }
        Set-GuardProgress 'verify'
        $stage = 'VERIFY'
        if ((Get-ProbeIP $egress.url) -ne $egress.ip) { throw 'VPN connectivity was lost after applying protection.' }
        foreach ($route in $probes) {
            if (Test-Tcp $route.address) { throw 'A direct verification route was still reachable.' }
        }
        if ($wfp) {
            $stage = 'WFP'
            Invoke-WfpWorker 'Verify'
        }
    } catch {
        if ($started) {
            $failedStage = $stage
            $stage = 'RESTORE'
            Set-GuardProgress 'restore'
            if ($upgrade) {
                # A failed Upgrade changed nothing (one transaction). After a
                # committed one, put the previously verified set back instead
                # of opening traffic.
                if ($upgraded) { Invoke-WfpWorker 'Rollback' }
            } elseif ($wfp) {
                Invoke-WfpWorker 'Remove'
            } else {
                Restore-Guard
            }
            $stage = $failedStage
        }
        throw
    } finally {
        if ($hostRoutes) { $hostRoutes | Remove-NetRoute -Confirm:$false }
    }
    Write-Output 'Verified: VPN HTTPS succeeds and direct verification routes are blocked.'
} catch {
    if ($Action -in @('Preflight','Enable','Disable','CleanLegacy','WfpEnable','WfpUpgrade','WfpDisable')) {
        [Console]::Error.WriteLine("TG_STAGE:$stage")
    }
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
