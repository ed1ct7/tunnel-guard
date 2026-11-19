param([switch] $StatusOnly)

$ErrorActionPreference = 'Stop'
$guardScript = Join-Path $PSScriptRoot 'server4-kill-switch.ps1'
$guardLog = Join-Path $PSScriptRoot 'firewall-kill-switch.log'

function Get-GuardState {
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'Server4KillSwitch-*' -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) {
        return 'Off'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $lockedProfiles = @($profiles | Where-Object {
        $_.Enabled -eq 'True' -and $_.DefaultOutboundAction -eq 'Block' -and
        $_.AllowLocalFirewallRules -eq 'False'
    })
    $enabledRules = @($rules | Where-Object Enabled -eq 'True')
    if ($lockedProfiles.Count -eq 3 -and $enabledRules.Count -eq 7) {
        return 'On'
    }
    'Partial'
}

if ($StatusOnly) {
    Get-GuardState
    return
}

$created = $false
$instance = [System.Threading.Mutex]::new($true, 'Local\Server4KillSwitchUI', [ref]$created)
if (-not $created) {
    $instance.Dispose()
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$window = New-Object System.Windows.Forms.Form
$window.Text = 'Kill switch — Server 4'
$window.ClientSize = [System.Drawing.Size]::new(470, 180)
$window.StartPosition = 'CenterScreen'
$window.FormBorderStyle = 'FixedDialog'
$window.AutoScaleMode = 'Dpi'
$window.MaximizeBox = $false

$heading = New-Object System.Windows.Forms.Label
$heading.Location = [System.Drawing.Point]::new(20, 16)
$heading.Size = [System.Drawing.Size]::new(430, 33)
$heading.Font = [System.Drawing.Font]::new('Segoe UI', 16)

$detail = New-Object System.Windows.Forms.Label
$detail.Location = [System.Drawing.Point]::new(22, 58)
$detail.Size = [System.Drawing.Size]::new(425, 68)
$detail.Font = [System.Drawing.Font]::new('Segoe UI', 10)

$enable = New-Object System.Windows.Forms.Button
$enable.Text = 'Включить'
$enable.Location = [System.Drawing.Point]::new(225, 130)
$enable.Size = [System.Drawing.Size]::new(106, 32)

$disable = New-Object System.Windows.Forms.Button
$disable.Text = 'Выключить'
$disable.Location = [System.Drawing.Point]::new(342, 130)
$disable.Size = [System.Drawing.Size]::new(106, 32)

$window.Controls.AddRange(@($heading, $detail, $enable, $disable))
$script:change = $null
$poll = New-Object System.Windows.Forms.Timer
$poll.Interval = 400

function Show-GuardState {
    $state = Get-GuardState
    $enable.Enabled = $state -eq 'Off'
    $disable.Enabled = $state -ne 'Off'
    switch ($state) {
        'On' {
            $heading.Text = 'Блокировка включена'
            $detail.Text = 'Chrome, Claude и другие обычные приложения выходят в интернет через Server 4. У Steam и Deadlock есть прямой доступ.'
        }
        'Off' {
            $heading.Text = 'Блокировка выключена'
            $detail.Text = 'Без VPN приложения могут использовать домашний IP. Чтобы снова включить блокировку, сначала подключи Server 4 в v2rayN.'
        }
        'Partial' {
            $heading.Text = 'Состояние блокировки не подтверждено'
            $detail.Text = 'Можно восстановить прежние правила кнопкой «Выключить».'
        }
    }
}

function Start-GuardChange([string] $Action) {
    $enable.Enabled = $false
    $disable.Enabled = $false
    $heading.Text = 'Меняются правила Windows'
    $detail.Text = 'Подтверди запрос Windows на права администратора.'
    try {
        $exe = Join-Path $PSHOME 'powershell.exe'
        $arguments = '-NoProfile -File "{0}" -Action {1}' -f $guardScript, $Action
        $script:change = Start-Process -FilePath $exe -ArgumentList $arguments `
            -Verb RunAs -WindowStyle Hidden -PassThru
        $poll.Start()
    } catch {
        Show-GuardState
        $detail.Text = 'Windows не запустила изменение правил.'
    }
}

$enable.Add_Click({ Start-GuardChange Enable })
$disable.Add_Click({
    $answer = [System.Windows.Forms.MessageBox]::Show(
        $window,
        'Закрой Claude и его вкладки перед отключением. Если VPN пропадёт, открытый Claude сможет использовать домашний IP.',
        'Выключить блокировку?',
        'YesNo',
        'Warning',
        'Button2'
    )
    if ($answer -eq 'Yes') {
        Start-GuardChange Restore
    }
})
$poll.Add_Tick({
    if ($script:change.HasExited) {
        $poll.Stop()
        $exitCode = $script:change.ExitCode
        $script:change.Dispose()
        $script:change = $null
        Show-GuardState
        if ($exitCode -ne 0) {
            $detail.Text = 'Изменение не завершилось. Проверь подключение Server 4 и попробуй ещё раз.'
            if (Test-Path -LiteralPath $guardLog) {
                $lastError = Get-Content -LiteralPath $guardLog | Where-Object { $_ -like 'ERROR:*' } | Select-Object -Last 1
                if ($lastError) {
                    $window.Text = 'Kill switch — Server 4 · ошибка'
                }
            }
        } else {
            $window.Text = 'Kill switch — Server 4'
        }
    }
})

try {
    Show-GuardState
    $null = $window.ShowDialog()
} finally {
    $poll.Dispose()
    $window.Dispose()
    $instance.ReleaseMutex()
    $instance.Dispose()
}
