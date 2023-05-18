Write-Host @"
    ____                       _____ __           __  __  
   / __ \_________  _____     / ___// /__  __  __/ /_/ /_ 
  / /_/ / ___/ __ \/ ___/_____\__ \/ / _ \/ / / / __/ __ \
 / ____/ /  / /_/ / /__/_____/__/ / /  __/ /_/ / /_/ / / /
/_/   /_/   \____/\___/     /____/_/\___/\__,_/\__/_/ /_/ 
-----------------------------------------------------------        
This PowerShell script provides valuable insights into a specific
process on a Windows system, facilitating the triaging process for
suspected malware. By retrieving detailed information about the 
process, such as its name, ID, owner, parent process details, 
working directory, network connections, loaded DLLs, and more,
this script assists in understanding the behavior and potential
threat posed by a suspected process.

Administrative credentials are recommended for best results.

                   Author: V-Kazimir
-----------------------------------------------------------
"@

$validInput = $false

while (-not $validInput) {
    $processId = Read-Host "Enter the Process ID (PID)"
    
    if ($processId -match '^\d+$') {
        $validInput = $true
    } else {
        Write-Host "Invalid input. Please enter an integer."
    }
}

try {
    $process = Get-Process -Id $processId -ErrorAction Stop
    $parentProcess = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $process.Id }

    Write-Host
    Write-Host "General Process Information:"
    Write-Host "--------------------"
    Write-Host "Process Name: $($process.ProcessName)"
    Write-Host "Process ID: $($process.Id)"
    Write-Host "Process Owner: $((Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $process.Id }).GetOwner().User)"

    if ($parentProcess) {
        $parentProcessId = $parentProcess.ParentProcessId
        $parentProcessExecutable = try { (Get-Process -Id $parentProcessId -ErrorAction Stop).Path } catch { "Unknown, might not be running" }
        Write-Host "Parent Process Name: $($parentProcessExecutable)"
        Write-Host "Parent Process ID: $($parentProcessId)"
    } else {
        Write-Host "Parent Process Name: Parent Process not running"
        Write-Host "Parent Process ID: N/A"
    }

    Write-Host "Working Directory: $($process.Path)"
    Write-Host "Start Time: $($process.StartTime)"
    Write-Host "Handles: $($process.Handles)"
    Write-Host "Memory Usage: $([math]::Round($process.WorkingSet64 / 1kb)) kilobytes"
    Write-Host
    Write-Host "Network Information:"
    Write-Host "--------------------"
    $tcpConnections = Get-NetTCPConnection -OwningProcess $process.Id -ErrorAction SilentlyContinue
    $udpEndpoints = Get-NetUDPEndpoint -OwningProcess $process.Id -ErrorAction SilentlyContinue

    if ($tcpConnections) {
        Write-Host "TCP socket(s) found:"
        $tcpConnections | Format-Table -AutoSize
    }

    if ($udpEndpoints) {
        Write-Host "UDP socket(s) found:"
        $udpEndpoints | Format-Table -AutoSize
    }

    if (-not $tcpConnections -and -not $udpEndpoints) {
        Write-Host "No TCP/UDP sockets found."
    }

    Write-Host
    Write-Host "Loaded DLLs:"
    Write-Host "--------------------"

    $dlls = $process | Select-Object -ExpandProperty Modules | Group-Object -Property FileName | Select-Object -ExpandProperty Name
    foreach ($dll in $dlls) {
        Write-Host "- $dll"
    }

    Write-Host
    Write-Host
}
catch {
    Write-Host "Failed to retrieve process information. Process ID may no longer be running."
}
