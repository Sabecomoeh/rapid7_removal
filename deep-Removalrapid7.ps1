#Requires -RunAsAdministrator
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Hardened Rapid7 Insight Agent removal script for Windows endpoints and Windows Server.

.DESCRIPTION
    This script is designed for situations where the Rapid7 Insight Agent must be removed
    cleanly and predictably, including cases where the normal uninstall path is broken,
    incomplete, or blocked by running processes / residual service registrations / stale
    uninstall registry entries.

    Design goals:
      - Use a supported uninstall path first, when discoverable from registry metadata.
      - Fall back to a surgical cleanup path only when necessary.
      - Produce full forensic logging to a unique temp file for audit / troubleshooting.
      - Use PowerShell best practices:
          * Advanced function and CmdletBinding
          * SupportsShouldProcess for -WhatIf / -Confirm
          * Structured try/catch/finally and classified errors
          * Minimal external dependencies (PowerShell + standard Windows utilities only)

.NOTES
    Run from an elevated PowerShell session.
    Tested conceptually for Windows 10/11 and Windows Server 2016–2022.

.PARAMETER TargetFolder
    Installation root for the Rapid7 Insight Agent.

.PARAMETER ServiceName
    Default Rapid7 Windows service name.

.PARAMETER DisplayNamePatterns
    DisplayName patterns used to locate uninstall registry entries.

.PARAMETER UninstallToken
    Optional uninstall token. If your environment requires an uninstall token for automated
    removal and the uninstall string supports it, the token will be appended when appropriate.

.PARAMETER SkipOfficialUninstall
    Skip the registry-based uninstall attempt and go straight to surgical cleanup.

.PARAMETER LogDirectory
    Directory under which a unique forensic log file will be created.

.PARAMETER PurgeInstallerProductKeys
    Also remove matching Windows Installer product metadata keys under:
      HKLM:\SOFTWARE\Classes\Installer\Products
    This is intentionally aggressive and should be used only as part of last-resort cleanup.

.EXAMPLE
    Uninstall-Rapid7InsightAgentHardened -WhatIf

.EXAMPLE
    Uninstall-Rapid7InsightAgentHardened -Confirm:$false

.EXAMPLE
    Uninstall-Rapid7InsightAgentHardened -UninstallToken 'YOURTOKEN' -Confirm:$false
#>

function Uninstall-Rapid7InsightAgentHardened {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TargetFolder = 'C:\Program Files\Rapid7\Insight Agent',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName = 'ir_agent',

        [Parameter()]
        [string[]]$DisplayNamePatterns = @(
            '*Rapid7 Insight Agent*',
            '*Insight Agent*',
            '*Rapid7*'
        ),

        [Parameter()]
        [string]$UninstallToken,

        [Parameter()]
        [switch]$SkipOfficialUninstall,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$LogDirectory = (Join-Path -Path $env:TEMP -ChildPath 'Rapid7_Removal'),

        [Parameter()]
        [switch]$PurgeInstallerProductKeys
    )

    begin {
        # region ===== Logging / runtime context =====

        $script:StartTime = Get-Date
        $script:ComputerName = $env:COMPUTERNAME
        $script:CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $script:LogFile = $null

        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }

        $script:LogFile = Join-Path -Path $LogDirectory -ChildPath ("Rapid7_InsightAgent_Removal_{0:yyyyMMdd_HHmmss}_{1}.log" -f $script:StartTime, $script:ComputerName)

        function Write-Log {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$Message,

                [Parameter()]
                [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
                [string]$Level = 'INFO'
            )

            $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $line = '{0} [{1}] {2}' -f $timestamp, $Level, $Message

            # Console output
            switch ($Level) {
                'INFO'  { Write-Host $line -ForegroundColor Cyan }
                'WARN'  { Write-Warning $Message }
                'ERROR' { Write-Error $Message }
                'DEBUG' { Write-Verbose $Message }
            }

            # File output
            Add-Content -Path $script:LogFile -Value $line
        }

        function Write-Section {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$Title
            )
            $banner = ('=' * 78)
            Write-Log -Message $banner -Level INFO
            Write-Log -Message $Title -Level INFO
            Write-Log -Message $banner -Level INFO
        }

        function Test-IsAdministrator {
            [CmdletBinding()]
            param()

            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        }

        function Get-RegistryUninstallEntries {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string[]]$Patterns
            )

            $paths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )

            $results = New-Object System.Collections.Generic.List[object]

            foreach ($path in $paths) {
                $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue

                foreach ($item in $items) {
                    # Enforce static properties via Select-Object to block strict-mode missing property exceptions.
                    $safeItem = $item | Select-Object -Property DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, PSPath, PSChildName

                    if ($null -eq $safeItem.DisplayName -or [string]::IsNullOrWhiteSpace($safeItem.DisplayName)) {
                        continue
                    }

                    foreach ($pattern in $Patterns) {
                        if ($safeItem.DisplayName -like $pattern) {
                            [void]$results.Add($safeItem)
                            break
                        }
                    }
                }
            }

            return $results | Sort-Object -Property PSPath -Unique
        }

        function Get-InstallerProductKeys {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string[]]$Patterns
            )

            $productRoot = 'HKLM:\SOFTWARE\Classes\Installer\Products'
            if (-not (Test-Path -LiteralPath $productRoot)) {
                return @()
            }

            $keys = foreach ($key in Get-ChildItem -Path $productRoot -ErrorAction SilentlyContinue) {
                try {
                    $item = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                    $safeItem = $item | Select-Object -Property ProductName, PSPath

                    if ($safeItem.ProductName) {
                        foreach ($pattern in $Patterns) {
                            if ($safeItem.ProductName -like $pattern) {
                                [pscustomobject]@{
                                    ProductName = $safeItem.ProductName
                                    PSPath      = $key.PSPath
                                }
                                break
                            }
                        }
                    }
                }
                catch {
                    Write-Log -Message ("Failed reading installer product key [{0}] - {1}" -f $key.PSPath, $_.Exception.Message) -Level WARN
                }
            }

            $keys | Sort-Object -Property PSPath -Unique
        }

        function Get-ServiceSafe {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$Name
            )
            try {
                Get-Service -Name $Name -ErrorAction Stop
            }
            catch {
                $null
            }
        }

        function Get-ProcessesByPathPrefix {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$PathPrefix
            )

            $matches = @()

            foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
                try {
                    if ($proc.Path -and $proc.Path.StartsWith($PathPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $matches += $proc
                    }
                }
                catch {
                    # Accessing .Path can fail for protected/system processes.
                }
            }

            $matches | Sort-Object -Property Id -Unique
        }

        function Split-CommandLine {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$CommandLine
            )

            $trimmed = $CommandLine.Trim()

            if ($trimmed -match '^\s*"([^"]+)"\s*(.*)$') {
                return [pscustomobject]@{
                    FilePath     = $matches[1]
                    ArgumentList = $matches[2]
                }
            }

            if ($trimmed -match '^\s*([^\s]+)\s*(.*)$') {
                return [pscustomobject]@{
                    FilePath     = $matches[1]
                    ArgumentList = $matches[2]
                }
            }

            throw "Unable to parse command line: $CommandLine"
        }

        function Invoke-ExternalCommand {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$FilePath,

                [Parameter()]
                [string]$ArgumentList,

                [Parameter()]
                [int[]]$SuccessExitCodes = @(0),

                [Parameter()]
                [string]$ActionDescription = 'Run external command'
            )

            $stdoutFile = Join-Path -Path $LogDirectory -ChildPath ("stdout_{0:yyyyMMdd_HHmmssfff}.txt" -f (Get-Date))
            $stderrFile = Join-Path -Path $LogDirectory -ChildPath ("stderr_{0:yyyyMMdd_HHmmssfff}.txt" -f (Get-Date))

            Write-Log -Message ("{0}: FilePath=[{1}] Arguments=[{2}]" -f $ActionDescription, $FilePath, $ArgumentList) -Level INFO

            $process = Start-Process -FilePath $FilePath `
                                     -ArgumentList $ArgumentList `
                                     -Wait `
                                     -PassThru `
                                     -NoNewWindow `
                                     -RedirectStandardOutput $stdoutFile `
                                     -RedirectStandardError $stderrFile

            $stdout = if (Test-Path -LiteralPath $stdoutFile) { Get-Content -Path $stdoutFile -Raw -ErrorAction SilentlyContinue } else { '' }
            $stderr = if (Test-Path -LiteralPath $stderrFile) { Get-Content -Path $stderrFile -Raw -ErrorAction SilentlyContinue } else { '' }

            if ($stdout) {
                Write-Log -Message ("STDOUT: {0}" -f ($stdout.Trim())) -Level DEBUG
            }
            if ($stderr) {
                Write-Log -Message ("STDERR: {0}" -f ($stderr.Trim())) -Level WARN
            }

            $result = [pscustomobject]@{
                ExitCode = $process.ExitCode
                StdOut   = $stdout
                StdErr   = $stderr
                FilePath = $FilePath
                Args     = $ArgumentList
            }

            if ($SuccessExitCodes -notcontains $result.ExitCode) {
                throw ("{0} failed. ExitCode={1}" -f $ActionDescription, $result.ExitCode)
            }

            return $result
        }

        function Test-OpenFilesLocalTrackingEnabled {
            [CmdletBinding()]
            param()

            try {
                $output = & openfiles /query /fo csv 2>&1
                $text = ($output | Out-String)

                if ($text -match 'maintain objects list' -or $text -match 'local open files') {
                    return $false
                }

                return $true
            }
            catch {
                return $false
            }
        }

        function Get-Rapid7State {
            [CmdletBinding()]
            param()

            $service = Get-ServiceSafe -Name $ServiceName
            $folderExists = Test-Path -LiteralPath $TargetFolder
            $uninstallEntries = Get-RegistryUninstallEntries -Patterns $DisplayNamePatterns
            $procByName = @()
            foreach ($name in @('insight_agent', 'ir_agent')) {
                $procByName += Get-Process -Name $name -ErrorAction SilentlyContinue
            }
            $procByPath = Get-ProcessesByPathPrefix -PathPrefix $TargetFolder

            [pscustomobject]@{
                FolderExists               = $folderExists
                ServiceExists              = [bool]$service
                ServiceStatus              = if ($service) { $service.Status.ToString() } else { $null }
                RegistryEntryCount         = @($uninstallEntries).Count
                ProcessCountByKnownName    = @($procByName).Count
                ProcessCountByFolderPrefix = @($procByPath).Count
                RegistryEntries            = $uninstallEntries
                Service                    = $service
                ProcessesByKnownName       = $procByName
                ProcessesByFolderPrefix    = $procByPath
            }
        }

        function Remove-RegistryKeySafe {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$Path,

                [Parameter()]
                [string]$Reason = 'Registry cleanup'
            )

            if (Test-Path -LiteralPath $Path) {
                if ($PSCmdlet.ShouldProcess($Path, 'Remove registry key')) {
                    try {
                        Write-Log -Message ("Removing registry key [{0}] Reason=[{1}]" -f $Path, $Reason) -Level WARN
                        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                        Write-Log -Message ("Removed registry key [{0}]" -f $Path) -Level INFO
                    }
                    catch [System.UnauthorizedAccessException] {
                        Write-Log -Message ("Registry permission failure removing [{0}] - {1}" -f $Path, $_.Exception.Message) -Level ERROR
                    }
                    catch {
                        Write-Log -Message ("Unexpected registry cleanup failure removing [{0}] - {1}" -f $Path, $_.Exception.Message) -Level ERROR
                    }
                }
            }
        }

        function Stop-ProcessSafe {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory, ValueFromPipeline)]
                [System.Diagnostics.Process]$ProcessObject
            )
            process {
                if ($PSCmdlet.ShouldProcess(("Process {0} (PID {1})" -f $ProcessObject.ProcessName, $ProcessObject.Id), 'Stop-Process -Force')) {
                    try {
                        Write-Log -Message ("Stopping process Name=[{0}] PID=[{1}] Path=[{2}]" -f $ProcessObject.ProcessName, $ProcessObject.Id, $ProcessObject.Path) -Level WARN
                    }
                    catch {
                        Write-Log -Message ("Stopping process Name=[{0}] PID=[{1}] Path=[unavailable]" -f $ProcessObject.ProcessName, $ProcessObject.Id) -Level WARN
                    }

                    try {
                        Stop-Process -Id $ProcessObject.Id -Force -ErrorAction Stop
                        Write-Log -Message ("Stopped process PID=[{0}]" -f $ProcessObject.Id) -Level INFO
                    }
                    catch [System.InvalidOperationException] {
                        Write-Log -Message ("Process stop failure PID=[{0}] - {1}" -f $ProcessObject.Id, $_.Exception.Message) -Level ERROR
                    }
                    catch {
                        Write-Log -Message ("Unexpected process stop failure PID=[{0}] - {1}" -f $ProcessObject.Id, $_.Exception.Message) -Level ERROR
                    }
                }
            }
        }

        function Remove-DirectorySafe {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$Path
            )

            if (-not (Test-Path -LiteralPath $Path)) {
                Write-Log -Message ("Directory not present, nothing to remove: [{0}]" -f $Path) -Level INFO
                return $true
            }

            if ($PSCmdlet.ShouldProcess($Path, 'Remove directory recursively')) {
                try {
                    Write-Log -Message ("Attempting directory removal: [{0}]" -f $Path) -Level INFO

                    try {
                        Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop |
                            Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc |
                            ForEach-Object {
                                Write-Log -Message ("PreDelete File=[{0}] Size=[{1}] CreatedUtc=[{2}] ModifiedUtc=[{3}]" -f $_.FullName, $_.Length, $_.CreationTimeUtc, $_.LastWriteTimeUtc) -Level DEBUG
                            }
                    }
                    catch {
                        Write-Log -Message ("Pre-removal inventory failed for [{0}] - {1}" -f $Path, $_.Exception.Message) -Level WARN
                    }

                    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
                    Write-Log -Message ("Removed directory: [{0}]" -f $Path) -Level INFO
                    return $true
                }
                catch [System.UnauthorizedAccessException] {
                    Write-Log -Message ("Filesystem access denied removing [{0}] - {1}" -f $Path, $_.Exception.Message) -Level ERROR
                }
                catch [System.IO.IOException] {
                    Write-Log -Message ("Filesystem IO failure removing [{0}] - {1}" -f $Path, $_.Exception.Message) -Level ERROR
                }
                catch {
                    Write-Log -Message ("Unexpected filesystem cleanup failure removing [{0}] - {1}" -f $Path, $_.Exception.Message) -Level ERROR
                }

                $trackingEnabled = Test-OpenFilesLocalTrackingEnabled
                if ($trackingEnabled) {
                    Write-Log -Message 'Attempting lock diagnostics via openfiles.exe ...' -Level INFO
                    try {
                        $csv = & openfiles /query /v /fo csv 2>&1 | ConvertFrom-Csv
                        $locks = $csv | Where-Object {
                            $_.'Open File (Path Name)' -like ('{0}*' -f $Path) -or
                            $_.'Open File (Path Name)' -like '*Rapid7*' -or
                            $_.'Open File (Path Name)' -like '*Insight Agent*'
                        }

                        if ($locks) {
                            foreach ($lock in $locks) {
                                Write-Log -Message ("LockDetected AccessedBy=[{0}] OpenFile=[{1}] ID=[{2}] Host=[{3}]" -f $lock.'Accessed By', $lock.'Open File (Path Name)', $lock.ID, $lock.Hostname) -Level ERROR
                            }
                        }
                        else {
                            Write-Log -Message 'openfiles.exe returned no matching locks for the target path.' -Level WARN
                        }
                    }
                    catch {
                        Write-Log -Message ("openfiles.exe diagnostics failed - {0}" -f $_.Exception.Message) -Level WARN
                    }
                }
                else {
                    Write-Log -Message 'openfiles.exe local tracking does not appear enabled. Local lock diagnostics may be incomplete until local tracking is enabled and the host is rebooted.' -Level WARN
                }

                Write-Log -Message 'Removal failed due to persistent lock or access issue. Recommended remediation: reboot the host and rerun the script. If the issue persists, engage vendor support before forced reinstallation.' -Level ERROR
                return $false
            }

            return $true
        }

        function Build-UninstallCommand {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [psobject]$RegistryEntry
            )

            $candidate = if ($RegistryEntry.QuietUninstallString) {
                $RegistryEntry.QuietUninstallString
            }
            else {
                $RegistryEntry.UninstallString
            }

            if (-not $candidate) {
                return $null
            }

            $resolved = $candidate.Trim()

            if ($resolved -match '(?i)msiexec(\.exe)?') {
                if ($resolved -notmatch '(?i)\s/x\s' -and $resolved -notmatch '(?i)\s/uninstall\s') {
                    if ($RegistryEntry.PSChildName -and $RegistryEntry.PSChildName -match '^\{[0-9A-Fa-f\-]+\}$') {
                        $resolved = "msiexec.exe /x $($RegistryEntry.PSChildName)"
                    }
                }

                if ($resolved -notmatch '(?i)\s/q') {
                    $resolved += ' /qn /norestart'
                }
            }

            if ($UninstallToken -and $resolved -notmatch '(?i)UNINSTALLTOKEN=') {
                $resolved += " UNINSTALLTOKEN=$UninstallToken"
            }

            return $resolved
        }

        # endregion ===== Logging / runtime context =====

        Write-Section -Title 'RAPID7 INSIGHT AGENT HARDENED REMOVAL START'
        Write-Log -Message ("Host=[{0}] User=[{1}] PSVersion=[{2}] PID=[{3}] LogFile=[{4}]" -f $script:ComputerName, $script:CurrentUser, $PSVersionTable.PSVersion, $PID, $script:LogFile) -Level INFO

        if (-not (Test-IsAdministrator)) {
            Write-Log -Message 'This script must be run as Administrator. Aborting.' -Level ERROR
            throw 'Administrative privileges are required.'
        }

        Write-Log -Message 'Administrative token confirmed.' -Level INFO
    }

    process {
        $result = [ordered]@{
            ComputerName                  = $script:ComputerName
            User                          = $script:CurrentUser
            StartTime                     = $script:StartTime
            EndTime                       = $null
            LogFile                       = $script:LogFile
            SupportedUninstallAttempted   = $false
            SupportedUninstallSucceeded   = $false
            SurgicalCleanupAttempted      = $false
            SurgicalCleanupSucceeded      = $false
            RebootRecommended             = $false
            FinalFolderExists             = $null
            FinalServiceExists            = $null
            FinalRegistryEntryCount       = $null
            Notes                         = @()
        }

        try {
            # -----------------------------------------------------------------
            # PHASE 1 - Discovery / baseline
            # -----------------------------------------------------------------
            Write-Section -Title 'PHASE 1 - DISCOVERY / BASELINE STATE'
            $initialState = Get-Rapid7State

            Write-Log -Message ("InitialState FolderExists=[{0}] ServiceExists=[{1}] ServiceStatus=[{2}] RegistryEntryCount=[{3}] ProcKnownNameCount=[{4}] ProcByFolderCount=[{5}]" -f `
                $initialState.FolderExists,
                $initialState.ServiceExists,
                $initialState.ServiceStatus,
                $initialState.RegistryEntryCount,
                $initialState.ProcessCountByKnownName,
                $initialState.ProcessCountByFolderPrefix) -Level INFO

            foreach ($entry in $initialState.RegistryEntries) {
                $dispName   = if ($entry.DisplayName) { $entry.DisplayName } else { '' }
                $dispVer    = if ($entry.DisplayVersion) { $entry.DisplayVersion } else { '' }
                $publisher  = if ($entry.Publisher) { $entry.Publisher } else { '' }
                $unString   = if ($entry.UninstallString) { $entry.UninstallString } else { '' }
                $qUnString  = if ($entry.QuietUninstallString) { $entry.QuietUninstallString } else { '' }
                $psPath     = if ($entry.PSPath) { $entry.PSPath } else { '' }

                Write-Log -Message ("RegistryEntry DisplayName=[{0}] DisplayVersion=[{1}] Publisher=[{2}] UninstallString=[{3}] QuietUninstallString=[{4}] PSPath=[{5}]" -f `
                    $dispName, $dispVer, $publisher, $unString, $qUnString, $psPath) -Level DEBUG
            }

            if (-not $initialState.FolderExists -and -not $initialState.ServiceExists -and $initialState.RegistryEntryCount -eq 0) {
                Write-Log -Message 'Rapid7 agent indicators were not found. Nothing to do.' -Level INFO
                $result.Notes += 'No install indicators found.'
            }

            # -----------------------------------------------------------------
            # PHASE 2 - Supported uninstall attempt (best practice first)
            # -----------------------------------------------------------------
            # HARDENED FIX: Wrap collection inside an explicit array block @(...) so strict-mode won't crash when RegistryEntries holds exactly 1 item.
            if (-not $SkipOfficialUninstall -and @($initialState.RegistryEntries).Count -gt 0) {
                Write-Section -Title 'PHASE 2 - SUPPORTED / REGISTRY-DISCOVERED UNINSTALL ATTEMPT'
                $result.SupportedUninstallAttempted = $true

                foreach ($entry in $initialState.RegistryEntries) {
                    $commandLine = Build-UninstallCommand -RegistryEntry $entry

                    if (-not $commandLine) {
                        $dispName = if ($entry.DisplayName) { $entry.DisplayName } else { 'Unknown' }
                        Write-Log -Message ("No executable uninstall string found for entry [{0}] at [{1}]. Skipping supported uninstall attempt for this entry." -f $dispName, $entry.PSPath) -Level WARN
                        continue
                    }

                    $parsed = Split-CommandLine -CommandLine $commandLine
                    $dispName = if ($entry.DisplayName) { $entry.DisplayName } else { 'Unknown' }

                    if ($PSCmdlet.ShouldProcess($dispName, "Run uninstall command: $commandLine")) {
                        try {
                            # HARDENED FIX: Prevent msiexec background process locks from execution freezes during a -WhatIf deployment mock run.
                            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('WhatIf')) {
                                Write-Log -Message "[WHATIF SIMULATION] Would execute external installer path: [$($parsed.FilePath)] with arguments: [$($parsed.ArgumentList)]" -Level INFO
                                continue
                            }

                            $cmdResult = Invoke-ExternalCommand -FilePath $parsed.FilePath `
                                                                -ArgumentList $parsed.ArgumentList `
                                                                -SuccessExitCodes @(0, 1605, 1614, 3010) `
                                                                -ActionDescription ("Uninstall [{0}]" -f $dispName)

                            Write-Log -Message ("Supported uninstall completed for [{0}] ExitCode=[{1}]" -f $dispName, $cmdResult.ExitCode) -Level INFO

                            if ($cmdResult.ExitCode -eq 3010) {
                                $result.RebootRecommended = $true
                                $result.Notes += 'Uninstaller returned 3010 (reboot required).'
                            }
                        }
                        catch {
                            Write-Log -Message ("Supported uninstall failed for [{0}] - {1}" -f $dispName, $_.Exception.Message) -Level ERROR
                            $result.Notes += ("Supported uninstall failed for [{0}]" -f $dispName)
                        }
                    }
                }

                Start-Sleep -Seconds 2

                $postSupportedState = Get-Rapid7State
                Write-Log -Message ("PostSupportedState FolderExists=[{0}] ServiceExists=[{1}] RegistryEntryCount=[{2}] ProcKnownNameCount=[{3}] ProcByFolderCount=[{4}]" -f `
                    $postSupportedState.FolderExists,
                    $postSupportedState.ServiceExists,
                    $postSupportedState.RegistryEntryCount,
                    $postSupportedState.ProcessCountByKnownName,
                    $postSupportedState.ProcessCountByFolderPrefix) -Level INFO

                if (-not $postSupportedState.FolderExists -and -not $postSupportedState.ServiceExists -and $postSupportedState.RegistryEntryCount -eq 0) {
                    $result.SupportedUninstallSucceeded = $true
                    Write-Log -Message 'Supported uninstall path appears to have removed all detected indicators.' -Level INFO
                }
                else {
                    Write-Log -Message 'Supported uninstall was incomplete or indicators remain. Proceeding to surgical cleanup.' -Level WARN
                }
            }
            elseif ($SkipOfficialUninstall) {
                Write-Log -Message 'SkipOfficialUninstall requested. Going directly to surgical cleanup.' -Level WARN
            }
            else {
                Write-Log -Message 'No uninstall registry entries found, so there is no supported uninstall command to invoke. Proceeding to surgical cleanup.' -Level WARN
            }

            # -----------------------------------------------------------------
            # PHASE 3 - Surgical cleanup (processes, service, files, registry)
            # -----------------------------------------------------------------
            Write-Section -Title 'PHASE 3 - SURGICAL CLEANUP'
            $result.SurgicalCleanupAttempted = $true

            $preSurgeryState = Get-Rapid7State

            # 3A. Kill known agent processes first.
            Write-Log -Message 'Subphase 3A - Stopping known agent processes.' -Level INFO
            foreach ($proc in $preSurgeryState.ProcessesByKnownName | Sort-Object -Property Id -Unique) {
                $proc | Stop-ProcessSafe
            }

            # 3B. Kill any process running from the target directory.
            Write-Log -Message 'Subphase 3B - Stopping processes executing from the target folder.' -Level INFO
            foreach ($proc in $preSurgeryState.ProcessesByFolderPrefix | Sort-Object -Property Id -Unique) {
                $proc | Stop-ProcessSafe
            }

            Start-Sleep -Milliseconds 750

            # 3C. Stop and delete the service registration.
            Write-Log -Message 'Subphase 3C - Service stop and service registration cleanup.' -Level INFO
            $service = Get-ServiceSafe -Name $ServiceName
            if ($service) {
                Write-Log -Message ("Service detected Name=[{0}] Status=[{1}] CanStop=[{2}]" -f $service.Name, $service.Status, $service.CanStop) -Level INFO

                if ($service.Status -ne 'Stopped') {
                    if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop-Service -Force')) {
                        try {
                            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                            Write-Log -Message ("Stopped service [{0}]" -f $ServiceName) -Level INFO
                        }
                        catch {
                            Write-Log -Message ("Service stop failure Name=[{0}] - {1}" -f $ServiceName, $_.Exception.Message) -Level ERROR
                        }
                    }
                }

                if ($PSCmdlet.ShouldProcess($ServiceName, 'sc.exe delete')) {
                    try {
                        $deleteResult = Invoke-ExternalCommand -FilePath 'sc.exe' `
                                                               -ArgumentList ("delete {0}" -f $ServiceName) `
                                                               -SuccessExitCodes @(0) `
                                                               -ActionDescription ("Delete service [{0}]" -f $ServiceName)

                        Write-Log -Message ("Service delete requested for [{0}] ExitCode=[{1}]" -f $ServiceName, $deleteResult.ExitCode) -Level INFO
                    }
                    catch {
                        Write-Log -Message ("Service delete failure Name=[{0}] - {1}" -f $ServiceName, $_.Exception.Message) -Level ERROR
                    }
                }
            }
            else {
                Write-Log -Message ("Service [{0}] not found. No service cleanup needed." -f $ServiceName) -Level INFO
            }

            Start-Sleep -Milliseconds 750

            # 3D. Remove installation directory.
            Write-Log -Message 'Subphase 3D - Remove installation directory.' -Level INFO
            $folderRemoved = Remove-DirectorySafe -Path $TargetFolder
            if (-not $folderRemoved) {
                $result.RebootRecommended = $true
                $result.Notes += 'Folder removal failed; reboot recommended due to possible lock.'
            }

            # 3E. Remove uninstall registry entries.
            Write-Log -Message 'Subphase 3E - Remove uninstall registry entries.' -Level INFO
            $remainingUninstallEntries = Get-RegistryUninstallEntries -Patterns $DisplayNamePatterns
            foreach ($entry in $remainingUninstallEntries) {
                $dispName = if ($entry.DisplayName) { $entry.DisplayName } else { 'Unknown' }
                Write-Log -Message ("Residual uninstall entry found DisplayName=[{0}] PSPath=[{1}]" -f $dispName, $entry.PSPath) -Level WARN
                Remove-RegistryKeySafe -Path $entry.PSPath -Reason 'Residual uninstall metadata'
            }

            # 3F. Optional, aggressive cleanup of Windows Installer product metadata.
            if ($PurgeInstallerProductKeys) {
                Write-Log -Message 'Subphase 3F - Purging matching Windows Installer product metadata keys (aggressive cleanup).' -Level WARN
                $productKeys = Get-InstallerProductKeys -Patterns $DisplayNamePatterns
                foreach ($productKey in $productKeys) {
                    Write-Log -Message ("Installer product key matched ProductName=[{0}] PSPath=[{1}]" -f $productKey.ProductName, $productKey.PSPath) -Level WARN
                    Remove-RegistryKeySafe -Path $productKey.PSPath -Reason 'Aggressive Windows Installer product metadata cleanup'
                }
            }
            else {
                Write-Log -Message 'Installer product metadata purge not requested; skipping aggressive Installer\Products cleanup.' -Level INFO
            }

            # -----------------------------------------------------------------
            # PHASE 4 - Final verification
            # -----------------------------------------------------------------
            Write-Section -Title 'PHASE 4 - FINAL VERIFICATION'
            $finalState = Get-Rapid7State

            $result.FinalFolderExists = $finalState.FolderExists
            $result.FinalServiceExists = $finalState.ServiceExists
            $result.FinalRegistryEntryCount = $finalState.RegistryEntryCount

            Write-Log -Message ("FinalState FolderExists=[{0}] ServiceExists=[{1}] ServiceStatus=[{2}] RegistryEntryCount=[{3}] ProcKnownNameCount=[{4}] ProcByFolderCount=[{5}]" -f `
                $finalState.FolderExists,
                $finalState.ServiceExists,
                $finalState.ServiceStatus,
                $finalState.RegistryEntryCount,
                $finalState.ProcessCountByKnownName,
                $finalState.ProcessCountByFolderPrefix) -Level INFO

            if (-not $finalState.FolderExists -and -not $finalState.ServiceExists -and $finalState.RegistryEntryCount -eq 0) {
                $result.SurgicalCleanupSucceeded = $true
                Write-Log -Message 'Rapid7 agent indicators are no longer present. Removal appears successful.' -Level INFO
            }
            else {
                $result.SurgicalCleanupSucceeded = $false
                Write-Log -Message 'One or more Rapid7 indicators still remain after cleanup. Review log details before reinstalling or escalating.' -Level ERROR

                if ($finalState.FolderExists -or $finalState.ProcessCountByKnownName -gt 0 -or $finalState.ProcessCountByFolderPrefix -gt 0) {
                    $result.RebootRecommended = $true
                }

                if ($finalState.FolderExists) {
                    $result.Notes += 'Folder still exists after cleanup.'
                }
                if ($finalState.ServiceExists) {
                    $result.Notes += 'Service still exists after cleanup.'
                }
                if ($finalState.RegistryEntryCount -gt 0) {
                    $result.Notes += 'Registry uninstall entries still exist after cleanup.'
                }
            }
        }
        catch {
            Write-Section -Title 'UNHANDLED FAILURE'
            Write-Log -Message ("Unhandled exception type=[{0}] message=[{1}]" -f $_.Exception.GetType().FullName, $_.Exception.Message) -Level ERROR
            if ($_.ScriptStackTrace) {
                Write-Log -Message ("ScriptStackTrace: {0}" -f $_.ScriptStackTrace) -Level ERROR
            }
            $result.Notes += ("Unhandled exception: {0}" -f $_.Exception.Message)
            $result.RebootRecommended = $true
            throw
        }
        finally {
            $result.EndTime = Get-Date

            Write-Section -Title 'SUMMARY'
            Write-Log -Message ("SupportedUninstallAttempted=[{0}] SupportedUninstallSucceeded=[{1}] SurgicalCleanupAttempted=[{2}] SurgicalCleanupSucceeded=[{3}] RebootRecommended=[{4}]" -f `
                $result.SupportedUninstallAttempted,
                $result.SupportedUninstallSucceeded,
                $result.SurgicalCleanupAttempted,
                $result.SurgicalCleanupSucceeded,
                $result.RebootRecommended) -Level INFO

            if ($result.Notes.Count -gt 0) {
                foreach ($note in $result.Notes) {
                    Write-Log -Message ("Note: {0}" -f $note) -Level WARN
                }
            }

            Write-Log -Message ("Elapsed=[{0}] LogFile=[{1}]" -f ((Get-Date) - $script:StartTime), $script:LogFile) -Level INFO
            Write-Section -Title 'RAPID7 INSIGHT AGENT HARDENED REMOVAL END'
        }

        [pscustomobject]$result
    }
}

# ---------------------------------------------------------------------------
# Standalone execution block
# ---------------------------------------------------------------------------
if ($MyInvocation.MyCommand.Path) {
    $params = @{}
    if ($PSBoundParameters.ContainsKey('WhatIf')) {
        $params['WhatIf'] = $PSBoundParameters['WhatIf']
    }
    else {
        $params['Confirm'] = $false
    }
    Uninstall-Rapid7InsightAgentHardened @params
}
