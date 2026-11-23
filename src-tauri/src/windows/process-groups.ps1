$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $session = (Get-Process -Id $PID).SessionId
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $known = @{}
    $owners = @{}
    $packages = @{}
    $finders = @($request.selectors | Where-Object kind -ne 'service')
    $serviceNames = @($request.selectors | Where-Object kind -eq 'service' | Select-Object -ExpandProperty value -Unique)
    if ($finders.kind -contains 'package_family') {
        foreach ($package in (Get-AppxPackage)) {
            if ($package.InstallLocation) {
                $family = $package.PackageFamilyName
                $packages[$family] = @($packages[$family]) + @($package.InstallLocation.TrimEnd('\') + '\')
            }
        }
    }

    function Get-Snapshot {
        $snapshot = @{}
        foreach ($item in (Get-CimInstance Win32_Process -Filter "SessionId = $session")) {
            if ($item.CreationDate) { $snapshot[[int]$item.ProcessId] = $item }
        }
        $snapshot
    }

    function Matches-Selector($item, $selector) {
        switch ($selector.kind) {
            'name' { return $item.Name -ieq $selector.value }
            'path' { return $item.ExecutablePath -ieq $selector.value }
            'package_family' {
                foreach ($directory in $packages[$selector.value]) {
                    if ($directory -and $item.ExecutablePath -and
                        $item.ExecutablePath.StartsWith($directory, [StringComparison]::OrdinalIgnoreCase)) { return $true }
                }
                return $false
            }
            'argument' {
                return $item.Name -ieq $selector.image -and $item.CommandLine -and
                    $item.CommandLine.IndexOf($selector.value, [StringComparison]::OrdinalIgnoreCase) -ge 0
            }
        }
        $false
    }

    function Find-Matches([hashtable] $snapshot) {
        $matched = @{}
        $parents = @{}
        foreach ($entry in $known.GetEnumerator()) {
            $current = $snapshot[$entry.Key]
            if (-not $current -or $current.CreationDate -eq $entry.Value.CreationDate) {
                $parents[$entry.Key] = $entry.Value
                if ($current) { $matched[$entry.Key] = $current }
            }
        }
        foreach ($item in $snapshot.Values) {
            foreach ($selector in $finders) {
                if (Matches-Selector $item $selector) {
                    $id = [int]$item.ProcessId
                    $matched[$id] = $item
                    $parents[$id] = $item
                    break
                }
            }
        }
        do {
            $added = $false
            foreach ($item in $snapshot.Values) {
                $id = [int]$item.ProcessId
                $parent = $parents[[int]$item.ParentProcessId]
                if (-not $matched.ContainsKey($id) -and $parent -and $item.CreationDate -ge $parent.CreationDate) {
                    $matched[$id] = $item
                    $parents[$id] = $item
                    $added = $true
                }
            }
        } while ($added)
        $matched
    }

    function Test-Owner($item) {
        $key = "$($item.ProcessId):$($item.CreationDate.Ticks)"
        if (-not $owners.ContainsKey($key)) {
            try {
                $result = Invoke-CimMethod -InputObject $item -MethodName GetOwnerSid
                $owners[$key] = $result.ReturnValue -eq 0 -and $result.Sid -eq $ownerSid
            } catch {
                $owners[$key] = $false
            }
        }
        $owners[$key]
    }

    function Get-CallerChain([hashtable] $snapshot) {
        $chain = @{}
        $cursor = $snapshot[[int]$PID]
        while ($cursor) {
            $id = [int]$cursor.ProcessId
            if ($chain.ContainsKey($id)) { break }
            $chain[$id] = $cursor.CreationDate
            $parent = $snapshot[[int]$cursor.ParentProcessId]
            if (-not $parent -or $parent.CreationDate -gt $cursor.CreationDate) { break }
            $cursor = $parent
        }
        $chain
    }

    function Format-Process($item) {
        [pscustomobject]@{pid=[int]$item.ProcessId;name=$item.Name;owned=[bool](Test-Owner $item)}
    }

    function Stop-Identity($item) {
        $process = $null
        try {
            $process = [Diagnostics.Process]::GetProcessById([int]$item.ProcessId)
            # Retain a handle so this PID cannot be reused before Kill().
            $null = $process.Handle
            $now = Get-CimInstance Win32_Process -Filter "ProcessId = $($item.ProcessId)"
            if (-not $now -or $now.CreationDate -ne $item.CreationDate) { return $false }
            if (-not (Test-Owner $now)) { return $false }
            $process.Kill()
            return $true
        } catch {
            return $false
        } finally {
            if ($process) { $process.Dispose() }
        }
    }

    $snapshot = Get-Snapshot
    $caller = Get-CallerChain $snapshot
    $initial = Find-Matches $snapshot
    $matchesCaller = @($initial.Values | Where-Object {
        $caller[[int]$_.ProcessId] -eq $_.CreationDate
    }).Count -gt 0
    $preview = @($initial.Values | Sort-Object ProcessId | ForEach-Object { Format-Process $_ })
    $services = @(foreach ($name in $serviceNames) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($service) { [pscustomobject]@{name=$service.Name;status=$service.Status.ToString();error=$null} }
    })
    if (-not $request.stop) {
        @{ matched=$preview; caller_in_group=$matchesCaller; services=$services } | ConvertTo-Json -Depth 5 -Compress
        exit 0
    }
    if ($matchesCaller) {
        throw 'Группа включает вызвавшее приложение. Запусти завершение из окна Tunnel Guard или из отдельной консоли.'
    }

    foreach ($service in $services) {
        if ($service.status -eq 'Stopped') { continue }
        try {
            $controller = Get-Service -Name $service.name -ErrorAction Stop
            if ($controller.Status -ne 'StopPending') {
                Stop-Service -InputObject $controller -ErrorAction Stop
            }
            $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(8))
        } catch {
            $service.error = $_.Exception.Message
        }
    }

    $stopped = @()
    $matched = $initial
    for ($pass=0; $pass -lt 3 -and $matched.Count -gt 0; $pass++) {
        foreach ($entry in $matched.GetEnumerator()) { $known[$entry.Key] = $entry.Value }
        # Stop parents first to prevent their helpers from respawning.
        foreach ($item in ($matched.Values | Sort-Object CreationDate,ProcessId)) {
            if ($caller[[int]$item.ProcessId] -eq $item.CreationDate -or -not (Test-Owner $item)) { continue }
            if (Stop-Identity $item) { $stopped += Format-Process $item }
        }
        Start-Sleep -Milliseconds 160
        $matched = Find-Matches (Get-Snapshot)
    }
    foreach ($service in $services) {
        $now = Get-Service -Name $service.name -ErrorAction SilentlyContinue
        $service.status = if ($now) { $now.Status.ToString() } else { 'Missing' }
    }
    $remaining = @($matched.Values | Sort-Object ProcessId | ForEach-Object { Format-Process $_ })
    $complete = $remaining.Count -eq 0 -and -not ($services | Where-Object {$_.status -notin @('Stopped','Missing')})
    @{matched=$preview;stopped=$stopped;remaining=$remaining;services=$services;complete=[bool]$complete} |
        ConvertTo-Json -Depth 5 -Compress
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
