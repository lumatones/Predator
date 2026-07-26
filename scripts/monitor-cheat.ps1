<#
.SYNOPSIS
    Predator -- Dynamic Cheat Analysis Toolkit
    Monitor dxwebsetup.exe execution in isolated session.

.USAGE
    powershell -ExecutionPolicy Bypass -File monitor-cheat.ps1 -Action snapshot -OutDir C:\monitor
    powershell -ExecutionPolicy Bypass -File monitor-cheat.ps1 -Action run -Target "FILE" -OutDir C:\monitor
    powershell -ExecutionPolicy Bypass -File monitor-cheat.ps1 -Action diff -OutDir C:\monitor
    powershell -ExecutionPolicy Bypass -File monitor-cheat.ps1 -Action cleanup -OutDir C:\monitor
#>

param(
    [ValidateSet('snapshot','run','diff','cleanup')]
    [string]$Action = 'diff',
    [string]$Target = '',
    [string]$OutDir = "$env:TEMP\predator-monitor"
)

$null = New-Item -ItemType Directory -Path $OutDir -Force

# =====================================================
# HELPERS
# =====================================================

function Get-ProcessSnapshot {
    param([string]$Path)
    $data = Get-Process | Select-Object Name, Id, CPU, PM, Path, StartTime,
        @{N='Modules';E={try{$_.Modules.ModuleName -join ';'}catch{''}}}
    $data | Export-Clixml -Path $Path
    Write-Host "  [OK] Processes: $($data.Count) saved"
}

function Get-RegistrySnapshot {
    param([string]$Path)
    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SYSTEM\CurrentControlSet\Services',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $data = @()
    foreach ($key in $keys) {
        if (Test-Path $key) {
            try {
                $items = Get-ItemProperty -Path $key -ErrorAction Stop
                $props = ($items.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | ForEach-Object {"$($_.Name)=$($_.Value)"}) -join '|'
                $data += [PSCustomObject]@{ Path = $key; Properties = $props }
            } catch { }
        }
    }
    $data | Export-Clixml -Path $Path
    Write-Host "  [OK] Registry: $($data.Count) keys saved"
}

function Get-FileSnapshot {
    param([string]$Path)
    $dirs = @(
        "$env:TEMP",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:ProgramData",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\System32\Tasks",
        "$env:SystemRoot\Prefetch"
    )
    $data = @()
    foreach ($dir in $dirs) {
        if (Test-Path $dir) {
            try {
                $items = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) } |
                    Select-Object FullName, Length, LastWriteTime, CreationTime
                $data += $items
            } catch { }
        }
    }
    $data | Export-Clixml -Path $Path
    Write-Host "  [OK] Files: $($data.Count) recent files saved"
}

function Get-NetworkSnapshot {
    param([string]$Path)
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        $connections | Export-Clixml -Path $Path
        Write-Host "  [OK] Network: $($connections.Count) connections saved"
    } catch {
        Write-Host "  [!!] Network snapshot not available (run as admin)"
        @() | Export-Clixml -Path $Path
    }
}

function Get-WmiSnapshot {
    param([string]$Path)
    try {
        $scheduled = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object {$_.State -ne 'Disabled'} |
            Select-Object TaskName, TaskPath, State, Actions
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, StartMode, PathName
        $data = @{ScheduledTasks = $scheduled; Services = $services}
        $data | Export-Clixml -Path $Path
        Write-Host "  [OK] Services & Tasks saved"
    } catch {
        Write-Host "  [!!] WMI snapshot not available (run as admin)"
        @() | Export-Clixml -Path $Path
    }
}

function Get-FullSnapshot {
    param([string]$Label)
    Write-Host "`n=== Snapshot: $Label ==="
    Get-ProcessSnapshot -Path (Join-Path $OutDir "processes_$Label.xml")
    Get-RegistrySnapshot -Path (Join-Path $OutDir "registry_$Label.xml")
    Get-FileSnapshot -Path (Join-Path $OutDir "files_$Label.xml")
    Get-NetworkSnapshot -Path (Join-Path $OutDir "network_$Label.xml")
    Get-WmiSnapshot -Path (Join-Path $OutDir "wmi_$Label.xml")
    Write-Host "  [OK] Snapshot '$Label' complete`n"
}

# =====================================================
# ACTIONS
# =====================================================

switch ($Action) {
    'snapshot' {
        Write-Host "========================================"
        Write-Host "  PREDATOR - System Snapshot (BEFORE)"
        Write-Host "========================================"
        Get-FullSnapshot -Label 'before'
        Write-Host "Snapshots saved to: $OutDir"
    }

    'run' {
        if (-not $Target -or -not (Test-Path $Target)) {
            Write-Error "Target file not found: $Target"
            exit 1
        }

        Write-Host "========================================"
        Write-Host "  PREDATOR - Running under monitor"
        Write-Host "========================================"
        Write-Host "Target: $Target"
        Write-Host "Monitor will capture for 5 minutes after launch`n"

        Get-FullSnapshot -Label 'before'

        $startTime = Get-Date
        Write-Host ">>> LAUNCHING at $startTime <<<`n"

        $proc = Start-Process -FilePath $Target -PassThru -WindowStyle Normal
        $targetPid = $proc.Id
        Write-Host "  Process started: PID $targetPid"

        $endTime = $startTime.AddMinutes(5)
        $reported = @{}

        while ((Get-Date) -lt $endTime) {
            Start-Sleep -Seconds 3

            try {
                $current = Get-Process
                $newProcs = $current | Where-Object { $_.StartTime -gt $startTime -and -not $reported[$_.Id] }
                foreach ($p in $newProcs) {
                    $reported[$p.Id] = $true
                    $path = try { $p.Path } catch { 'N/A' }
                    $cpu = '{0:N1}' -f $p.CPU
                    $mb = '{0:N0}' -f ($p.PM / 1MB)
                    Write-Host "  [NEW] PID=$($p.Id) NAME=$($p.Name) CPU=${cpu}s MEM=${mb}MB PATH=$path"
                }
            } catch { }

            $recentFiles = Get-ChildItem -Path "$env:TEMP" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -gt $startTime } |
                Select-Object -First 5
            foreach ($f in $recentFiles) {
                $key = "file:$($f.FullName)"
                if (-not $reported[$key]) {
                    $reported[$key] = $true
                    $size = '{0:N1}KB' -f ($f.Length / 1KB)
                    Write-Host "  [FILE] $($f.FullName) ($size)"
                }
            }
        }

        Write-Host "`n<<< MONITORING COMPLETE >>>"
        Get-FullSnapshot -Label 'after'

        Write-Host "`n=== Comparing snapshots... ==="
        & $PSCommandPath -Action diff -OutDir $OutDir

        Write-Host "`nDone! Results saved to: $OutDir"
    }

    'diff' {
        Write-Host "========================================"
        Write-Host "  PREDATOR - Snapshot Comparison"
        Write-Host "========================================"

        $before = "$OutDir\processes_before.xml"
        $after = "$OutDir\processes_after.xml"

        if (-not (Test-Path $before) -or -not (Test-Path $after)) {
            Write-Error "Snapshots not found in $OutDir. Run -Action run first."
            exit 1
        }

        $procsBefore = @{}
        foreach ($p in (Import-Clixml $before)) { $procsBefore[$p.Id] = $p.Name }
        $procsAfter = Import-Clixml $after
        $newProcs = $procsAfter | Where-Object { -not $procsBefore.ContainsKey($_.Id) -and $_.Id -ne 0 }

        Write-Host "`n--- NEW PROCESSES ($($newProcs.Count)) ---" -ForegroundColor Red
        if ($newProcs.Count -eq 0) { Write-Host "  (none)" }
        else {
            $newProcs | Format-Table Id, Name, @{N='CPU(s)';E={'{0:N1}' -f $_.CPU}},
                @{N='MB';E={'{0:N0}' -f ($_.PM / 1MB)}}, Path -AutoSize | Out-String | Write-Host
        }

        Write-Host "--- REGISTRY CHANGES ---" -ForegroundColor Yellow
        try {
            $regBefore = @{}
            foreach ($r in (Import-Clixml "$OutDir\registry_before.xml")) { $regBefore[$r.Path] = $r.Properties }
            $regAfter = Import-Clixml "$OutDir\registry_after.xml"
            foreach ($r in $regAfter) {
                $beforeVal = $regBefore[$r.Path]
                if ($beforeVal -ne $r.Properties) {
                    Write-Host "  [KEY] $($r.Path)" -ForegroundColor Yellow
                    if ($beforeVal) { Write-Host "     Before: $beforeVal" }
                    Write-Host "     After:  $($r.Properties)"
                }
            }
        } catch { Write-Host "  [!!] Registry diff error" }

        Write-Host "`n--- NEW/MODIFIED FILES ---" -ForegroundColor Cyan
        try {
            $filesBefore = @{}
            foreach ($f in (Import-Clixml "$OutDir\files_before.xml")) { $filesBefore[$f.FullName] = $f }
            $filesAfter = Import-Clixml "$OutDir\files_after.xml"
            $newFiles = $filesAfter | Where-Object { -not $filesBefore.ContainsKey($_.FullName) }
            if ($newFiles.Count -eq 0) { Write-Host "  (none)" }
            else {
                $newFiles | Select-Object FullName, @{N='KB';E={'{0:N0}' -f ($_.Length / 1KB)}},
                    LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host
            }
        } catch { Write-Host "  [!!] File diff error" }

        Write-Host "--- NETWORK CONNECTIONS (after) ---" -ForegroundColor Green
        try {
            $net = Import-Clixml "$OutDir\network_after.xml"
            if ($net.Count -eq 0) { Write-Host "  (none)" }
            else {
                $remoteOnly = $net | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
                $remoteOnly | Select-Object LocalAddress, RemoteAddress, RemotePort, State |
                    Format-Table -AutoSize | Out-String | Write-Host
            }
        } catch { Write-Host "  [!!] Network diff error" }
    }

    'cleanup' {
        Write-Host "========================================"
        Write-Host "  PREDATOR - Cleanup / Rollback"
        Write-Host "========================================"

        Write-Host "  Looking for dxwebsetup.exe process..."
        try {
            $targetProcs = Get-Process -Name 'dxwebsetup' -ErrorAction SilentlyContinue
            foreach ($p in $targetProcs) {
                Write-Host "  Killing: dxwebsetup.exe (PID $($p.Id))"
                Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $($p.Id)" -ErrorAction SilentlyContinue |
                    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            }
        } catch { }

        Write-Host "  Checking for orphaned child processes..."
        try {
            $allProcs = Get-Process
            $twoMinAgo = (Get-Date).AddMinutes(-2)
            foreach ($p in $allProcs) {
                if ($p.StartTime -gt $twoMinAgo) {
                    try {
                        $parent = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
                        $ppid = $parent.ParentProcessId
                        $parentProc = Get-Process -Id $ppid -ErrorAction SilentlyContinue
                        if (-not $parentProc -or $parentProc.StartTime -lt $twoMinAgo.AddMinutes(-5)) {
                            Write-Host "  Killing orphan: $($p.Name) (PID $($p.Id))"
                            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                        }
                    } catch { }
                }
            }
        } catch { }

        Write-Host "  Cleaning recent temp files..."
        $tempDirs = @("$env:TEMP", "$env:APPDATA\Temp", "$env:LOCALAPPDATA\Temp")
        foreach ($dir in $tempDirs) {
            if (Test-Path $dir) {
                $recent = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-10) }
                foreach ($f in $recent) {
                    Write-Host "  Deleting: $($f.FullName)"
                    Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }

        Write-Host "  Checking registry Run keys..."
        $runPaths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        )
        foreach ($key in $runPaths) {
            if (Test-Path $key) {
                try {
                    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                    foreach ($prop in $props.PSObject.Properties) {
                        if ($prop.Name -notlike 'PS*') {
                            $val = "$($prop.Value)"
                            if ($val -match 'dxwebsetup') {
                                Write-Host "  Cleaning registry: $key -> $($prop.Name)"
                                Remove-ItemProperty -Path $key -Name $prop.Name -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                } catch { }
            }
        }

        Write-Host "  Checking network connections..."
        try {
            $safePorts = @(53, 80, 443, 3389, 22, 21, 25, 110, 143, 993, 587, 465)
            $suspiciousConns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.RemotePort -notin $safePorts -and
                    $_.State -eq 'Established' -and
                    $_.RemoteAddress -notlike '192.168.*' -and
                    $_.RemoteAddress -notlike '10.*' -and
                    $_.RemoteAddress -notlike '172.1[6-9].*' -and
                    $_.RemoteAddress -notlike '172.2[0-9].*' -and
                    $_.RemoteAddress -notlike '172.3[0-1].*' -and
                    $_.RemoteAddress -notlike '127.*' -and
                    $_.RemoteAddress -notlike '::1' -and
                    $_.RemoteAddress -notlike 'localhost'
                }
            foreach ($conn in $suspiciousConns) {
                try {
                    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc -and $proc.StartTime -gt (Get-Date).AddMinutes(-2)) {
                        Write-Host "  [!!] Suspicious connection: $($proc.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                        Write-Host "  Killing process: $($proc.Name) (PID $($conn.OwningProcess))"
                        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
                    }
                } catch { }
            }
        } catch { }

        Write-Host "`n  [OK] Cleanup complete!"
        Write-Host "  [!!] RECOMMENDED: Restart your computer to ensure full cleanup."
    }
}
