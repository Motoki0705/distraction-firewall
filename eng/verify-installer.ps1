[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Version,

    [string]$PackageDirectory = 'artifacts/package',

    [switch]$RequireSigning,

    [switch]$RequireDeferredActiveUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if (-not [System.IO.Path]::IsPathRooted($PackageDirectory)) {
    $PackageDirectory = Join-Path $repositoryRoot $PackageDirectory
}
$PackageDirectory = [System.IO.Path]::GetFullPath($PackageDirectory)

function Assert-Contract {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-WixSource {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $repositoryRoot $RelativePath
    [xml]$document = Get-Content -LiteralPath $path -Raw
    $namespaceManager = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespaceManager.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
    $namespaceManager.AddNamespace('util', 'http://wixtoolset.org/schemas/v4/wxs/util')
    $namespaceManager.AddNamespace('bal', 'http://wixtoolset.org/schemas/v4/wxs/bal')
    return [pscustomobject]@{
        Path = $path
        Text = Get-Content -LiteralPath $path -Raw
        Document = $document
        NamespaceManager = $namespaceManager
    }
}

function Get-XmlAttribute {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$Name
    )

    return $Node.GetAttribute($Name)
}

function Open-MsiDatabase {
    param([Parameter(Mandatory)][string]$Path)

    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        $database = $installer.OpenDatabase($Path, 0)
    }
    catch {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
        throw
    }

    return [pscustomobject]@{
        Installer = $installer
        Database = $database
        Path = $Path
    }
}

function Close-MsiDatabase {
    param([Parameter(Mandatory)]$Context)

    if ($null -ne $Context.Database) {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($Context.Database)
    }
    if ($null -ne $Context.Installer) {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($Context.Installer)
    }
}

function Get-MsiTableNames {
    param([Parameter(Mandatory)]$Context)

    $view = $Context.Database.OpenView('SELECT `Name` FROM `_Tables`')
    try {
        $null = $view.Execute()
        $names = [System.Collections.Generic.List[string]]::new()
        while ($true) {
            $record = $view.Fetch()
            if ($null -eq $record) {
                break
            }
            try {
                $names.Add($record.StringData(1))
            }
            finally {
                [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
            }
        }
        return @($names)
    }
    finally {
        $null = $view.Close()
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

function Get-MsiTableRows {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Table
    )

    Assert-Contract ($Table -match '^[A-Za-z_][A-Za-z0-9_]*$') "Unsafe MSI table identifier: $Table"
    $columnQuery = 'SELECT `Name` FROM `_Columns` WHERE `Table`=''{0}'' ORDER BY `Number`' -f $Table
    $columnView = $Context.Database.OpenView($columnQuery)
    try {
        $null = $columnView.Execute()
        $columns = [System.Collections.Generic.List[string]]::new()
        while ($true) {
            $record = $columnView.Fetch()
            if ($null -eq $record) {
                break
            }
            try {
                $columns.Add($record.StringData(1))
            }
            finally {
                [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
            }
        }
    }
    finally {
        $null = $columnView.Close()
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($columnView)
    }

    Assert-Contract ($columns.Count -gt 0) "MSI table is missing or has no columns: $Table"
    $view = $Context.Database.OpenView(('SELECT * FROM `{0}`' -f $Table))
    try {
        $null = $view.Execute()
        $rows = [System.Collections.Generic.List[object]]::new()
        while ($true) {
            $record = $view.Fetch()
            if ($null -eq $record) {
                break
            }
            try {
                $row = [ordered]@{}
                for ($index = 0; $index -lt $columns.Count; $index++) {
                    $row[$columns[$index]] = $record.StringData($index + 1)
                }
                $rows.Add([pscustomobject]$row)
            }
            finally {
                [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
            }
        }
        return @($rows)
    }
    finally {
        $null = $view.Close()
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

function Get-MsiSummaryProperty {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][int]$Property
    )

    $summary = $Context.Database.SummaryInformation(0)
    try {
        return [string]$summary.Property($Property)
    }
    finally {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)
    }
}

function Get-LongMsiName {
    param([Parameter(Mandatory)][string]$Value)

    if ($Value.Contains('|')) {
        return $Value.Substring($Value.LastIndexOf('|') + 1)
    }
    return $Value
}

function Get-PeMachine {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $reader = [System.IO.BinaryReader]::new($stream)
    try {
        Assert-Contract ($reader.ReadUInt16() -eq 0x5A4D) "File is not a PE image: $Path"
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        Assert-Contract ($peOffset -ge 0x40 -and $peOffset -le ($stream.Length - 6)) "PE header offset is invalid: $Path"
        $stream.Position = $peOffset
        Assert-Contract ($reader.ReadUInt32() -eq 0x00004550) "PE signature is invalid: $Path"
        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Invoke-MsiAdministrativeImage {
    param(
        [Parameter(Mandatory)][string]$MsiPath,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogPath
    )

    $null = New-Item -ItemType Directory -Path $Destination -Force
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $arguments = @(
        '/a'
        ('"{0}"' -f $MsiPath)
        '/qn'
        '/norestart'
        ('TARGETDIR="{0}"' -f $Destination)
        '/L*v'
        ('"{0}"' -f $LogPath)
    )
    $process = Start-Process -FilePath $msiexec -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    $exitCode = $process.ExitCode
    if ($exitCode -notin @(0, 3010)) {
        throw "Administrative image extraction failed for $MsiPath with exit code $exitCode. Log: $LogPath"
    }
}

function Invoke-BundleExtraction {
    param(
        [Parameter(Mandatory)][string]$SetupPath,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$IntermediateDirectory,
        [Parameter(Mandatory)][string]$LogPath
    )

    $null = New-Item -ItemType Directory -Path $Destination -Force
    $null = New-Item -ItemType Directory -Path $IntermediateDirectory -Force
    $nugetRoot = $env:NUGET_PACKAGES
    if ([string]::IsNullOrWhiteSpace($nugetRoot)) {
        $nugetRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) '.nuget\packages'
    }
    $wixCli = Join-Path $nugetRoot 'wixtoolset.sdk\5.0.2\tools\net6.0\wix.dll'
    Assert-Contract (Test-Path -LiteralPath $wixCli -PathType Leaf) "Pinned WiX 5.0.2 CLI is unavailable for Burn extraction: $wixCli"
    $output = @(
        & dotnet $wixCli burn extract $SetupPath -o $Destination -intermediateFolder $IntermediateDirectory 2>&1
    )
    $exitCode = $LASTEXITCODE
    [System.IO.File]::WriteAllLines($LogPath, [string[]]$output)
    if ($exitCode -ne 0) {
        throw "Burn extraction failed for $SetupPath with exit code $exitCode. Log: $LogPath"
    }
}

function Assert-SelfContainedEntryPoint {
    param([Parameter(Mandatory)][string]$EntryPoint)

    Assert-Contract (Test-Path -LiteralPath $EntryPoint -PathType Leaf) "Expected entry point is missing from administrative image: $EntryPoint"
    Assert-Contract ((Get-PeMachine -Path $EntryPoint) -eq 0x8664) "Entry point is not an AMD64 PE image: $EntryPoint"
    $directory = Split-Path -Parent $EntryPoint
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($EntryPoint)
    foreach ($fileName in @("$baseName.runtimeconfig.json", 'coreclr.dll', 'hostfxr.dll', 'hostpolicy.dll')) {
        Assert-Contract (Test-Path -LiteralPath (Join-Path $directory $fileName) -PathType Leaf) "Self-contained payload file is missing beside ${EntryPoint}: $fileName"
    }
}

function Remove-VerifiedTemporaryTree {
    param([Parameter(Mandatory)][string]$Path)

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $directorySeparators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $temporaryPrefix = $temporaryRoot.TrimEnd($directorySeparators) + [System.IO.Path]::DirectorySeparatorChar
    $leaf = Split-Path -Leaf $resolvedPath
    Assert-Contract ($resolvedPath.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) "Refusing to recursively remove a path outside the temporary directory: $resolvedPath"
    Assert-Contract ($leaf.StartsWith('distraction-firewall-installer-verify-', [StringComparison]::Ordinal)) "Refusing to recursively remove an unexpected temporary path: $resolvedPath"
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Container)) {
        return
    }
    $reparsePoints = @(
        Get-ChildItem -LiteralPath $resolvedPath -Force -Recurse |
            Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 }
    )
    Assert-Contract ($reparsePoints.Count -eq 0) "Refusing to recursively remove a verification tree containing a reparse point: $resolvedPath"
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try {
            Remove-Item -LiteralPath $resolvedPath -Recurse -Force -ErrorAction Stop
            return
        }
        catch {
            if ($attempt -eq 20) {
                throw
            }
            [System.Threading.Thread]::Sleep(250)
        }
    }
}

$semanticVersionPattern = '^(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?<prerelease>(?:0|[1-9]\d*|[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[A-Za-z-][0-9A-Za-z-]*))*))?$'
$versionMatch = [regex]::Match($Version, $semanticVersionPattern)
if (-not $versionMatch.Success) {
    throw "Version must be SemVer without build metadata: $Version"
}

$isStable = -not $versionMatch.Groups['prerelease'].Success
if ($isStable) {
    $RequireSigning = $true
    $RequireDeferredActiveUninstall = $true
}

$appMsi = Join-Path $PackageDirectory "distraction-firewall-app-$Version-win-x64.msi"
$runtimeMsi = Join-Path $PackageDirectory "distraction-firewall-runtime-$Version-win-x64.msi"
$setupExe = Join-Path $PackageDirectory "distraction-firewall-setup-$Version-win-x64.exe"
$expectedArtifacts = @($appMsi, $runtimeMsi, $setupExe)
foreach ($artifact in $expectedArtifacts) {
    Assert-Contract (Test-Path -LiteralPath $artifact -PathType Leaf) "Expected package artifact is missing: $artifact"
    Assert-Contract ((Get-Item -LiteralPath $artifact).Length -gt 0) "Package artifact is empty: $artifact"
}

$statusPath = Join-Path $repositoryRoot 'installer\deferred-active-uninstall.status.json'
$status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
Assert-Contract ($status.capability -eq 'deferred-active-uninstall' -and $status.implemented -is [bool]) "Deferred active uninstall status is malformed: $statusPath"
Assert-Contract (-not $status.implemented -or @($status.evidence).Count -gt 0) 'Deferred active uninstall is marked implemented without verification evidence.'
Assert-Contract (-not $RequireDeferredActiveUninstall -or $status.implemented) 'Deferred active uninstall is required but remains explicitly unimplemented.'

[xml]$installerProperties = Get-Content -LiteralPath (Join-Path $repositoryRoot 'installer\Directory.Build.props') -Raw
$declaredImplementation = $installerProperties.Project.PropertyGroup.DeferredActiveUninstallImplemented
Assert-Contract (-not [string]::IsNullOrWhiteSpace($declaredImplementation)) 'DeferredActiveUninstallImplemented is not declared in installer/Directory.Build.props.'
Assert-Contract ([Convert]::ToBoolean($declaredImplementation) -eq $status.implemented) 'The MSBuild capability declaration does not match deferred-active-uninstall.status.json.'
$gateText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'installer\Directory.Build.targets') -Raw
Assert-Contract ($gateText -match 'RequireDeferredActiveUninstall' -and $gateText -match 'DeferredActiveUninstallImplemented') 'The stable deferred-active-uninstall MSBuild gate is missing or malformed.'

$appSource = Get-WixSource -RelativePath 'installer\App\Package.wxs'
$runtimeSource = Get-WixSource -RelativePath 'installer\Runtime\Package.wxs'
$bundleSource = Get-WixSource -RelativePath 'installer\Bundle\Bundle.wxs'
$runtimeOwnerSidConditions = @(
    'ACTION = "ADMIN" OR Installed OR UserSID'
    'ACTION = "ADMIN" OR Installed OR (UserSID <> "S-1-0-0" AND UserSID <> "S-1-1-0" AND UserSID <> "S-1-2-0" AND UserSID <> "S-1-5-7" AND UserSID <> "S-1-5-11" AND UserSID <> "S-1-5-18")'
    'ACTION = "ADMIN" OR Installed OR (UserSID <> "S-1-5-19" AND UserSID <> "S-1-5-20" AND UserSID <> "S-1-5-32-544" AND UserSID <> "S-1-5-32-545" AND UserSID <> "S-1-5-32-546")'
)
$appPackage = $appSource.Document.SelectSingleNode('/w:Wix/w:Package', $appSource.NamespaceManager)
$runtimePackage = $runtimeSource.Document.SelectSingleNode('/w:Wix/w:Package', $runtimeSource.NamespaceManager)
$bundle = $bundleSource.Document.SelectSingleNode('/w:Wix/w:Bundle', $bundleSource.NamespaceManager)
Assert-Contract ($null -ne $appPackage -and $null -ne $runtimePackage -and $null -ne $bundle) 'An installer source is missing its Package or Bundle root.'
Assert-Contract (-not $appPackage.HasAttribute('Id') -and -not $runtimePackage.HasAttribute('Id') -and -not $bundle.HasAttribute('Id')) 'WiX v5 packages and bundle must use fixed UpgradeCode values, not the WiX v6 Id attribute.'
$upgradeCodes = @($appPackage.GetAttribute('UpgradeCode'), $runtimePackage.GetAttribute('UpgradeCode'), $bundle.GetAttribute('UpgradeCode'))
Assert-Contract (@($upgradeCodes | Select-Object -Unique).Count -eq 3 -and @($upgradeCodes | Where-Object { $_ -notmatch '^\{[0-9A-F-]{36}\}$' }).Count -eq 0) 'App, Runtime, and Bundle must have distinct fixed UpgradeCode GUIDs.'

foreach ($projectPath in @(
    'installer\App\DistractionFirewall.App.Installer.wixproj',
    'installer\Runtime\DistractionFirewall.Runtime.Installer.wixproj',
    'installer\Bundle\DistractionFirewall.Bundle.wixproj'
)) {
    $projectText = Get-Content -LiteralPath (Join-Path $repositoryRoot $projectPath) -Raw
    Assert-Contract ($projectText -match 'WixToolset\.Sdk/5\.0\.2') "$projectPath is not deliberately pinned to WixToolset.Sdk 5.0.2."
    Assert-Contract ($projectText -notmatch 'WixToolset\.Sdk/[67]') "$projectPath unexpectedly references WiX 6 or 7."
}
$centralPackagesText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'installer\Directory.Packages.props') -Raw
Assert-Contract ($centralPackagesText -match 'WixToolset\.BootstrapperApplications\.wixext.+\[5\.0\.2\]' -and $centralPackagesText -match 'WixToolset\.Util\.wixext.+\[5\.0\.2\]') 'WiX extensions are not exactly pinned to 5.0.2.'
$packagingText = (Get-Content -LiteralPath (Join-Path $repositoryRoot 'eng\package.ps1') -Raw) + (Get-Content -LiteralPath (Join-Path $repositoryRoot '.github\workflows\release.yml') -Raw)
Assert-Contract ($packagingText -notmatch 'WIX_OSMF_EULA_ACCEPTED|AcceptEula|WixEulaAcceptance') 'Obsolete WiX 7 OSMF acceptance coupling remains in packaging or release automation.'

$appInstallDirectory = $appSource.Document.SelectSingleNode("//w:StandardDirectory[@Id='ProgramFiles64Folder']/w:Directory[@Id='AppInstallFolder' and @Name='Distraction Firewall']", $appSource.NamespaceManager)
$runtimeInstallDirectory = $runtimeSource.Document.SelectSingleNode("//w:StandardDirectory[@Id='ProgramFiles64Folder']/w:Directory[@Id='RuntimeInstallFolder' and @Name='Distraction Firewall Lease Runtime']", $runtimeSource.NamespaceManager)
Assert-Contract ($null -ne $appInstallDirectory) 'App MSI does not own Program Files\Distraction Firewall.'
Assert-Contract ($null -ne $runtimeInstallDirectory) 'Runtime MSI does not own Program Files\Distraction Firewall Lease Runtime.'
Assert-Contract ($appSource.Text -notmatch 'Distraction Firewall Lease Runtime|DistractionFirewallActivation|active-lease\.json|RuntimeDataFolder') 'App MSI contains Runtime-owned paths or resources.'

foreach ($source in @($appSource, $runtimeSource)) {
    $launchConditions = @($source.Document.SelectNodes('//w:Launch', $source.NamespaceManager) | ForEach-Object { $_.GetAttribute('Condition') })
    $platformConditions = @($launchConditions | Where-Object { $_ -match 'ACTION = "ADMIN"' -and $_ -match 'VersionNT64' -and $_ -match 'DF_WINDOWS_BUILD >= 22000' -and $_ -match 'DF_WINDOWS_INSTALLATION_TYPE = "Client"' })
    Assert-Contract ($platformConditions.Count -eq 1) "$($source.Path) must have exactly one strict Windows 11 client x64 launch condition with an administrative-image exception."
}
$runtimeOwnerSidLaunch = @($runtimeSource.Document.SelectNodes('//w:Launch', $runtimeSource.NamespaceManager) | Where-Object { $runtimeOwnerSidConditions -contains $_.GetAttribute('Condition') })
Assert-Contract ($runtimeOwnerSidLaunch.Count -eq $runtimeOwnerSidConditions.Count -and @($runtimeOwnerSidLaunch | Where-Object { $_.GetAttribute('Message') -notmatch 'same signed-in user' }).Count -eq 0) 'Runtime MSI must reject missing, service-account, and broad owner SIDs on a new install while preserving the administrative-image/installed-product exceptions.'

$appMarker = $appSource.Document.SelectSingleNode("//w:Property[@Id='DF_DEFERRED_ACTIVE_UNINSTALL_IMPLEMENTED']", $appSource.NamespaceManager)
$runtimeMarker = $runtimeSource.Document.SelectSingleNode("//w:Property[@Id='DF_DEFERRED_ACTIVE_UNINSTALL_IMPLEMENTED']", $runtimeSource.NamespaceManager)
$expectedMarker = if ($status.implemented) { '1' } else { '0' }
Assert-Contract ($null -ne $appMarker -and $appMarker.GetAttribute('Value') -eq $expectedMarker -and $null -ne $runtimeMarker -and $runtimeMarker.GetAttribute('Value') -eq $expectedMarker) 'Installer capability markers do not match the deferred-uninstall status file.'

$runtimeArp = $runtimeSource.Document.SelectSingleNode("//w:Property[@Id='ARPSYSTEMCOMPONENT' and @Value='1']", $runtimeSource.NamespaceManager)
$appArp = $appSource.Document.SelectSingleNode("//w:Property[@Id='ARPSYSTEMCOMPONENT']", $appSource.NamespaceManager)
Assert-Contract ($null -ne $runtimeArp -and $null -eq $appArp) 'Runtime MSI must be hidden in ARP while App MSI remains visible.'
$shortcut = $appSource.Document.SelectSingleNode("//w:Shortcut[@Id='AppStartMenuShortcut' and @Directory='ApplicationProgramsFolder']", $appSource.NamespaceManager)
Assert-Contract ($null -ne $shortcut) 'App Start menu shortcut is missing.'
Assert-Contract ($appSource.Text -match 'CliFolder' -and $appSource.Text -match 'CliPublish') 'App MSI does not include the CLI payload.'

$serviceInstall = $runtimeSource.Document.SelectSingleNode("//w:ServiceInstall[@Name='DistractionFirewallActivation']", $runtimeSource.NamespaceManager)
$serviceControl = $runtimeSource.Document.SelectSingleNode("//w:ServiceControl[@Name='DistractionFirewallActivation']", $runtimeSource.NamespaceManager)
Assert-Contract ($null -ne $serviceInstall -and $serviceInstall.GetAttribute('Account') -eq 'LocalSystem' -and $serviceInstall.GetAttribute('Start') -eq 'auto' -and $serviceInstall.GetAttribute('Type') -eq 'ownProcess' -and $serviceInstall.GetAttribute('Arguments') -eq '--service') 'Activation service must be an automatic LocalSystem own-process service with the fixed --service argument.'
Assert-Contract ($null -ne $serviceControl -and $serviceControl.GetAttribute('Start') -eq 'install' -and $serviceControl.GetAttribute('Stop') -eq 'both' -and $serviceControl.GetAttribute('Remove') -eq 'uninstall' -and $serviceControl.GetAttribute('Wait') -eq 'yes') 'Activation service control lifecycle is incomplete.'
$serviceConfig = $serviceInstall.SelectSingleNode('w:ServiceConfig', $runtimeSource.NamespaceManager)
$coreFailureConfigs = @($runtimeSource.Document.SelectNodes('//w:ServiceConfigFailureActions', $runtimeSource.NamespaceManager))
$utilFailureConfigs = @($serviceInstall.SelectNodes('util:ServiceConfig', $runtimeSource.NamespaceManager))
Assert-Contract ($null -ne $serviceConfig -and $serviceConfig.GetAttribute('DelayedAutoStart') -eq 'yes' -and $serviceConfig.GetAttribute('FailureActionsWhen') -eq 'failedToStopOrReturnedError') 'Activation service delayed start or returned-error failure handling is missing.'
Assert-Contract ($coreFailureConfigs.Count -eq 0) 'Runtime authoring must not use the unreliable MSI 5 MsiServiceConfigFailureActions path.'
Assert-Contract ($utilFailureConfigs.Count -eq 1 -and $utilFailureConfigs[0].GetAttribute('FirstFailureActionType') -eq 'restart' -and $utilFailureConfigs[0].GetAttribute('SecondFailureActionType') -eq 'restart' -and $utilFailureConfigs[0].GetAttribute('ThirdFailureActionType') -eq 'restart' -and $utilFailureConfigs[0].GetAttribute('ResetPeriodInDays') -eq '1' -and $utilFailureConfigs[0].GetAttribute('RestartServiceDelayInSeconds') -eq '5') 'Activation service must use exactly one WiX Util rollback-aware recovery action with three five-second restarts and a one-day reset period.'

$finalizerFile = $runtimeSource.Document.SelectSingleNode("//w:Component[@Id='FinalizerExecutableComponent']/w:File[@Id='FinalizerExecutable' and @KeyPath='yes']", $runtimeSource.NamespaceManager)
$runtimeGuard = $runtimeSource.Document.SelectSingleNode("//w:CustomAction[@Id='GuardRuntimeMutation']", $runtimeSource.NamespaceManager)
$runtimeGuardSequence = $runtimeSource.Document.SelectSingleNode("//w:InstallExecuteSequence/w:Custom[@Action='GuardRuntimeMutation']", $runtimeSource.NamespaceManager)
$runtimeCleanup = $runtimeSource.Document.SelectSingleNode("//w:CustomAction[@Id='CleanupRuntimeInstallation']", $runtimeSource.NamespaceManager)
$runtimeCleanupSequence = $runtimeSource.Document.SelectSingleNode("//w:InstallExecuteSequence/w:Custom[@Action='CleanupRuntimeInstallation']", $runtimeSource.NamespaceManager)
Assert-Contract ($null -ne $finalizerFile -and $finalizerFile.GetAttribute('Source') -match 'FinalizerPublish.+distraction-firewall-finalizer\.exe$') 'The installed finalizer executable must be an explicit Runtime MSI file for the mutation guard.'
Assert-Contract ($null -ne $runtimeGuard -and $runtimeGuard.GetAttribute('FileRef') -eq 'FinalizerExecutable' -and $runtimeGuard.GetAttribute('ExeCommand') -eq 'guard-runtime-uninstall' -and $runtimeGuard.GetAttribute('Execute') -eq 'deferred' -and $runtimeGuard.GetAttribute('Impersonate') -eq 'no' -and $runtimeGuard.GetAttribute('Return') -eq 'check') 'Runtime mutation guard must be a checked deferred no-impersonation executable custom action.'
Assert-Contract ($null -ne $runtimeGuardSequence -and $runtimeGuardSequence.GetAttribute('After') -eq 'StopServices' -and $runtimeGuardSequence.GetAttribute('Condition') -eq 'Installed AND (REMOVE~="ALL" OR REINSTALL OR PATCH)') 'Runtime mutation guard must cover installed removal/upgrade/repair after StopServices.'
Assert-Contract ($null -ne $runtimeCleanup -and $runtimeCleanup.GetAttribute('FileRef') -eq 'FinalizerExecutable' -and $runtimeCleanup.GetAttribute('ExeCommand') -eq 'cleanup-runtime-installation' -and $runtimeCleanup.GetAttribute('Execute') -eq 'deferred' -and $runtimeCleanup.GetAttribute('Impersonate') -eq 'no' -and $runtimeCleanup.GetAttribute('Return') -eq 'check') 'Runtime installation cleanup must be a checked deferred no-impersonation finalizer action.'
Assert-Contract ($null -ne $runtimeCleanupSequence -and $runtimeCleanupSequence.GetAttribute('After') -eq 'GuardRuntimeMutation' -and $runtimeCleanupSequence.GetAttribute('Condition') -eq 'Installed AND REMOVE~="ALL"') 'Runtime installation cleanup must run only for full installed-product removal after the active guard.'

$directoryAcl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$fileAcl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
$directoryPermissionNodes = @($runtimeSource.Document.SelectNodes("//w:CreateFolder/w:PermissionEx[@Sddl='$directoryAcl']", $runtimeSource.NamespaceManager))
$filePermissionNodes = @($runtimeSource.Document.SelectNodes("//w:File/w:PermissionEx[@Sddl='$fileAcl']", $runtimeSource.NamespaceManager))
Assert-Contract ($directoryPermissionNodes.Count -eq 4) 'Runtime v1, ownership-ledger, dns, and dns\observations must have protected SYSTEM/Administrators directory ACLs.'
Assert-Contract ($filePermissionNodes.Count -eq 1) 'Only the installer-seeded observed-addresses file should have the protected file ACL.'
Assert-Contract ($runtimeSource.Text -notmatch 'DnsTargetSnapshotComponent|Name="target-snapshot\.json"') 'Runtime MSI must not seed the per-lease target snapshot.'

$seed = $runtimeSource.Document.SelectSingleNode("//w:Component[@Id='RuntimeInstallerSeedComponent']", $runtimeSource.NamespaceManager)
Assert-Contract ($null -ne $seed -and $seed.GetAttribute('Bitness') -eq 'always64' -and $seed.GetAttribute('NeverOverwrite') -eq 'yes') 'Runtime installer seed must be 64-bit and preserve its first owner across repair/upgrade.'
$ownerSeed = $seed.SelectSingleNode("w:RegistryValue[@Name='OwnerSid']", $runtimeSource.NamespaceManager)
$instanceSeed = $seed.SelectSingleNode("w:RegistryValue[@Name='ProductInstanceId']", $runtimeSource.NamespaceManager)
$dataRootSeed = $seed.SelectSingleNode("w:RegistryValue[@Name='DataRoot']", $runtimeSource.NamespaceManager)
Assert-Contract ($null -ne $ownerSeed -and $ownerSeed.GetAttribute('Value') -eq '[UserSID]' -and $ownerSeed.GetAttribute('KeyPath') -eq 'yes') 'Runtime OwnerSid must be seeded from Windows Installer UserSID as the registry key path.'
Assert-Contract ($null -ne $instanceSeed -and $instanceSeed.GetAttribute('Value') -eq 'Motoki0705.DistractionFirewall.Runtime.v1') 'Runtime ProductInstanceId seed is missing or incorrect.'
Assert-Contract ($null -ne $dataRootSeed -and $dataRootSeed.GetAttribute('Value') -eq '[RuntimeDataFolder]') 'Runtime fixed DataRoot registry value is missing.'
$cleanup = $seed.SelectSingleNode("util:RemoveFolderEx[@Id='RemoveRuntimeDataTree']", $runtimeSource.NamespaceManager)
$cleanupPropertySet = $runtimeSource.Document.SelectSingleNode("//w:SetProperty[@Id='DfRuntimeDataRoot']", $runtimeSource.NamespaceManager)
Assert-Contract ($null -ne $cleanup -and $cleanup.GetAttribute('Property') -eq 'DfRuntimeDataRoot' -and $cleanup.GetAttribute('On') -eq 'uninstall' -and $cleanup.GetAttribute('Condition') -eq 'NOT DF_ACTIVE_LEASE_FILE') 'Runtime recursive cleanup must target only the private property and only inactive uninstall.'
Assert-Contract ($null -ne $cleanupPropertySet -and $cleanupPropertySet.GetAttribute('Value') -eq '[DF_RUNTIME_DATA_ROOT_FROM_REGISTRY]' -and $cleanupPropertySet.GetAttribute('After') -eq 'AppSearch') 'Runtime cleanup private property must be copied from the protected HKLM registry search immediately after AppSearch.'

$runtimeLaunchConditions = @($runtimeSource.Document.SelectNodes('//w:Launch', $runtimeSource.NamespaceManager) | ForEach-Object { $_.GetAttribute('Condition') })
Assert-Contract ($runtimeLaunchConditions -contains 'ACTION = "ADMIN" OR Installed OR NOT DF_ACTIVE_LEASE_FILE') 'Active lease does not block Runtime install/major upgrade.'
Assert-Contract ($runtimeLaunchConditions -contains 'NOT (Installed AND REMOVE~="ALL" AND DF_ACTIVE_LEASE_FILE)') 'Active lease does not block Runtime uninstall.'
Assert-Contract ($runtimeLaunchConditions -contains 'NOT (Installed AND (REINSTALL OR PATCH) AND DF_ACTIVE_LEASE_FILE)') 'Active lease does not block Runtime repair/patch.'

$fixturePath = Join-Path $repositoryRoot 'installer\Runtime\fixtures\observed-addresses.json'
$fixtureBytes = [System.IO.File]::ReadAllBytes($fixturePath)
Assert-Contract (-not ($fixtureBytes.Length -ge 3 -and $fixtureBytes[0] -eq 0xEF -and $fixtureBytes[1] -eq 0xBB -and $fixtureBytes[2] -eq 0xBF)) 'Observed-addresses fixture must be UTF-8 without BOM.'
$fixture = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
$fixtureProperties = @($fixture.PSObject.Properties.Name | Sort-Object)
Assert-Contract (($fixtureProperties -join ',') -eq 'observations,schema_version' -and $fixture.schema_version -eq 1 -and @($fixture.observations).Count -eq 0) 'Observed-addresses fixture must be exactly schema_version 1 with an empty observations array.'

$chainPackages = @($bundleSource.Document.SelectNodes('/w:Wix/w:Bundle/w:Chain/w:MsiPackage', $bundleSource.NamespaceManager))
$chain = $bundleSource.Document.SelectSingleNode('/w:Wix/w:Bundle/w:Chain', $bundleSource.NamespaceManager)
Assert-Contract ($null -ne $chain -and $chain.GetAttribute('DisableRollback') -eq 'yes') 'Burn chain rollback must be disabled so a Runtime active-lease refusal cannot reinstall the already-removed App.'
Assert-Contract ($chainPackages.Count -eq 2 -and $chainPackages[0].GetAttribute('Id') -eq 'RuntimeMsi' -and $chainPackages[1].GetAttribute('Id') -eq 'AppMsi') 'Burn chain must install Runtime first and App second so uninstall removes App before a Runtime active-lease refusal.'
Assert-Contract ($chainPackages[0].GetAttribute('Visible') -eq 'no' -and $chainPackages[1].GetAttribute('Visible') -eq 'yes') 'Burn must hide Runtime MSI and expose App MSI in ARP.'

$appDatabase = Open-MsiDatabase -Path $appMsi
$runtimeDatabase = Open-MsiDatabase -Path $runtimeMsi
try {
    $appTables = @(Get-MsiTableNames -Context $appDatabase)
    $runtimeTables = @(Get-MsiTableNames -Context $runtimeDatabase)
    foreach ($requiredTable in @('Property', 'Directory', 'Component', 'File', 'Shortcut', 'LaunchCondition')) {
        Assert-Contract ($appTables -contains $requiredTable) "App MSI table is missing: $requiredTable"
    }
    foreach ($requiredTable in @('Property', 'Directory', 'Component', 'File', 'Registry', 'ServiceInstall', 'ServiceControl', 'MsiServiceConfig', 'Wix4ServiceConfig', 'MsiLockPermissionsEx', 'LaunchCondition', 'AppSearch', 'DrLocator', 'RegLocator', 'CustomAction', 'Wix4RemoveFolderEx', 'InstallExecuteSequence')) {
        Assert-Contract ($runtimeTables -contains $requiredTable) "Runtime MSI table is missing: $requiredTable"
    }
    Assert-Contract ($runtimeTables -notcontains 'MsiServiceConfigFailureActions') 'Runtime MSI must not contain the unreliable MsiServiceConfigFailureActions table.'
    Assert-Contract ($appTables -notcontains 'ServiceInstall') 'App MSI unexpectedly owns a Windows service.'
    Assert-Contract ((Get-MsiSummaryProperty -Context $appDatabase -Property 7) -match '^x64;') 'App MSI summary template is not x64.'
    Assert-Contract ((Get-MsiSummaryProperty -Context $runtimeDatabase -Property 7) -match '^x64;') 'Runtime MSI summary template is not x64.'
    Assert-Contract ((Get-MsiSummaryProperty -Context $appDatabase -Property 14) -eq '500' -and (Get-MsiSummaryProperty -Context $runtimeDatabase -Property 14) -eq '500') 'MSIs do not require Windows Installer 5.0.'

    $appProperties = @(Get-MsiTableRows -Context $appDatabase -Table 'Property')
    $runtimeProperties = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'Property')
    Assert-Contract (@($appProperties | Where-Object { $_.Property -eq 'ARPSYSTEMCOMPONENT' }).Count -eq 0) 'App MSI is unexpectedly hidden from ARP.'
    Assert-Contract (@($runtimeProperties | Where-Object { $_.Property -eq 'ARPSYSTEMCOMPONENT' -and $_.Value -eq '1' }).Count -eq 1) 'Runtime MSI is not hidden from ARP.'
    Assert-Contract (@($runtimeProperties | Where-Object { $_.Property -eq 'SecureCustomProperties' -and $_.Value -match 'DF_ACTIVE_LEASE_FILE' -and $_.Value -match 'DF_RUNTIME_DATA_ROOT_FROM_REGISTRY' }).Count -eq 1) 'Active marker and cleanup registry search are not secured across elevation.'

    $appDirectories = @(Get-MsiTableRows -Context $appDatabase -Table 'Directory')
    $runtimeDirectories = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'Directory')
    Assert-Contract (@($appDirectories | Where-Object { $_.Directory -eq 'AppInstallFolder' -and (Get-LongMsiName $_.DefaultDir) -eq 'Distraction Firewall' }).Count -eq 1) 'App MSI directory table lacks its dedicated app root.'
    Assert-Contract (@($appDirectories | Where-Object { (Get-LongMsiName $_.DefaultDir) -eq 'Distraction Firewall Lease Runtime' }).Count -eq 0) 'App MSI directory table crosses into the Runtime root.'
    Assert-Contract (@($runtimeDirectories | Where-Object { $_.Directory -eq 'RuntimeInstallFolder' -and (Get-LongMsiName $_.DefaultDir) -eq 'Distraction Firewall Lease Runtime' }).Count -eq 1) 'Runtime MSI directory table lacks its dedicated Runtime root.'

    $appFiles = @(Get-MsiTableRows -Context $appDatabase -Table 'File')
    $runtimeFiles = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'File')
    $appFileNames = @($appFiles | ForEach-Object { Get-LongMsiName $_.FileName })
    $runtimeFileNames = @($runtimeFiles | ForEach-Object { Get-LongMsiName $_.FileName })
    Assert-Contract ($appFileNames -contains 'distraction-firewall.exe' -and $appFileNames -contains 'distraction-firewall-cli.exe') 'App MSI lacks the UI or CLI entry point.'
    foreach ($runtimeEntryPoint in @('distraction-firewall-activation-service.exe', 'distraction-firewall-lease-worker.exe', 'distraction-firewall-dns.exe', 'distraction-firewall-finalizer.exe')) {
        Assert-Contract ($runtimeFileNames -contains $runtimeEntryPoint) "Runtime MSI entry point is missing: $runtimeEntryPoint"
    }
    Assert-Contract (@($runtimeFiles | Where-Object { $_.File -eq 'FinalizerExecutable' -and (Get-LongMsiName $_.FileName) -eq 'distraction-firewall-finalizer.exe' }).Count -eq 1) 'Runtime MSI finalizer is not addressable by the uninstall guard File key.'
    Assert-Contract ($runtimeFileNames -contains 'observed-addresses.json') 'Runtime MSI lacks the empty observed-address store.'
    Assert-Contract ($runtimeFileNames -notcontains 'target-snapshot.json') 'Runtime MSI improperly seeds the per-lease target snapshot.'
    Assert-Contract (@($appFileNames + $runtimeFileNames | Where-Object { $_ -like '*.pdb' }).Count -eq 0) 'Installer payload contains PDB files.'

    $shortcuts = @(Get-MsiTableRows -Context $appDatabase -Table 'Shortcut')
    Assert-Contract (@($shortcuts | Where-Object { (Get-LongMsiName $_.Name) -eq 'Distraction Firewall' }).Count -eq 1) 'App MSI shortcut table is missing the UI shortcut.'

    $registryRows = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'Registry')
    Assert-Contract (@($registryRows | Where-Object { $_.Root -eq '2' -and $_.Key -eq 'SOFTWARE\Motoki0705\DistractionFirewall\Runtime' -and $_.Name -eq 'OwnerSid' -and $_.Value -eq '[UserSID]' }).Count -eq 1) 'Runtime MSI Registry table lacks the 64-bit OwnerSid seed.'
    Assert-Contract (@($registryRows | Where-Object { $_.Name -eq 'ProductInstanceId' -and $_.Value -eq 'Motoki0705.DistractionFirewall.Runtime.v1' }).Count -eq 1) 'Runtime MSI Registry table lacks ProductInstanceId.'
    Assert-Contract (@($registryRows | Where-Object { $_.Name -eq 'DataRoot' -and $_.Value -eq '[RuntimeDataFolder]' }).Count -eq 1) 'Runtime MSI Registry table lacks the fixed DataRoot value.'
    $components = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'Component')
    $seedComponent = @($components | Where-Object { $_.Component -eq 'RuntimeInstallerSeedComponent' })
    Assert-Contract ($seedComponent.Count -eq 1 -and (([int]$seedComponent[0].Attributes -band 0x180) -eq 0x180)) 'Runtime seed component is not both 64-bit and NeverOverwrite.'

    $services = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'ServiceInstall')
    $service = @($services | Where-Object { $_.Name -eq 'DistractionFirewallActivation' })
    Assert-Contract ($service.Count -eq 1 -and $service[0].ServiceType -eq '16' -and $service[0].StartType -eq '2' -and (([int]$service[0].ErrorControl -band 1) -eq 1) -and $service[0].StartName -eq 'LocalSystem' -and $service[0].Arguments -eq '--service') 'Runtime MSI ServiceInstall row is incorrect.'
    $controls = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'ServiceControl')
    $control = @($controls | Where-Object { $_.Name -eq 'DistractionFirewallActivation' })
    Assert-Contract ($control.Count -eq 1 -and (([int]$control[0].Event -band 0xA3) -eq 0xA3) -and $control[0].Wait -eq '1') 'Runtime MSI ServiceControl row does not start/install, stop/both, remove/uninstall, and wait.'
    $serviceConfigurations = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'MsiServiceConfig')
    Assert-Contract (@($serviceConfigurations | Where-Object { $_.Name -eq 'DistractionFirewallActivation' -and $_.Event -eq '5' -and $_.ConfigType -eq '3' -and $_.Argument -eq '1' }).Count -eq 1) 'Runtime MSI does not set delayed automatic start.'
    Assert-Contract (@($serviceConfigurations | Where-Object { $_.Name -eq 'DistractionFirewallActivation' -and $_.Event -eq '5' -and $_.ConfigType -eq '4' -and $_.Argument -eq '1' }).Count -eq 1) 'Runtime MSI does not apply failure actions to returned errors.'
    $failureActions = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'Wix4ServiceConfig')
    Assert-Contract ($failureActions.Count -eq 1 -and $failureActions[0].ServiceName -eq 'DistractionFirewallActivation' -and $failureActions[0].Component_ -eq 'ActivationServiceComponent' -and $failureActions[0].NewService -eq '1' -and $failureActions[0].FirstFailureActionType -eq 'restart' -and $failureActions[0].SecondFailureActionType -eq 'restart' -and $failureActions[0].ThirdFailureActionType -eq 'restart' -and $failureActions[0].ResetPeriodInDays -eq '1' -and $failureActions[0].RestartServiceDelayInSeconds -eq '5') 'Runtime MSI WiX Util failure-action row is incorrect.'

    $customActions = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'CustomAction')
    $serviceConfigCustomActions = @(
        [pscustomobject]@{ Action = 'Wix4SchedServiceConfig_X64'; Target = 'SchedServiceConfig'; Type = 1 },
        [pscustomobject]@{ Action = 'Wix4ExecServiceConfig_X64'; Target = 'ExecServiceConfig'; Type = 3073 },
        [pscustomobject]@{ Action = 'Wix4RollbackServiceConfig_X64'; Target = 'RollbackServiceConfig'; Type = 3329 }
    )
    $serviceConfigCustomActionRows = @($customActions | Where-Object { $_.Action -match '^Wix4(Sched|Exec|Rollback)ServiceConfig_' })
    Assert-Contract ($serviceConfigCustomActionRows.Count -eq 3) 'Runtime MSI must contain only the x64 WiX Util service recovery schedule, execute, and rollback custom actions.'
    foreach ($expectedAction in $serviceConfigCustomActions) {
        $rows = @($customActions | Where-Object { $_.Action -eq $expectedAction.Action -and [int]$_.Type -eq $expectedAction.Type -and $_.Source -eq 'Wix4UtilCA_X64' -and $_.Target -eq $expectedAction.Target })
        Assert-Contract ($rows.Count -eq 1) "Runtime MSI is missing or weakening the x64 WiX Util service recovery custom action: $($expectedAction.Action)"
    }

    $executeSequence = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'InstallExecuteSequence')
    $installServicesSequence = @($executeSequence | Where-Object { $_.Action -eq 'InstallServices' })
    $serviceConfigSequence = @($executeSequence | Where-Object { $_.Action -eq 'Wix4SchedServiceConfig_X64' })
    $msiConfigureServicesSequence = @($executeSequence | Where-Object { $_.Action -eq 'MsiConfigureServices' })
    $startServicesSequence = @($executeSequence | Where-Object { $_.Action -eq 'StartServices' })
    Assert-Contract ($installServicesSequence.Count -eq 1 -and $serviceConfigSequence.Count -eq 1 -and $msiConfigureServicesSequence.Count -eq 1 -and $startServicesSequence.Count -eq 1 -and $serviceConfigSequence[0].Condition -eq 'NOT REMOVE~="ALL" AND VersionNT > 400' -and [int]$installServicesSequence[0].Sequence -lt [int]$serviceConfigSequence[0].Sequence -and [int]$serviceConfigSequence[0].Sequence -lt [int]$msiConfigureServicesSequence[0].Sequence -and [int]$msiConfigureServicesSequence[0].Sequence -lt [int]$startServicesSequence[0].Sequence) 'WiX Util service recovery must be scheduled after service installation and before MSI delayed-start configuration and service start.'

    $permissionRows = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'MsiLockPermissionsEx')
    Assert-Contract (@($permissionRows | Where-Object { $_.Table -eq 'CreateFolder' -and $_.SDDLText -eq $directoryAcl }).Count -eq 4) 'Runtime MSI directory ACL rows are missing or too broad.'
    Assert-Contract (@($permissionRows | Where-Object { $_.Table -eq 'File' -and $_.LockObject -eq 'ObservedAddressesFile' -and $_.SDDLText -eq $fileAcl }).Count -eq 1) 'Runtime MSI observed-address file ACL row is missing or too broad.'
    Assert-Contract (@($permissionRows | Where-Object { $_.LockObject -eq 'DnsTargetSnapshot' }).Count -eq 0) 'Runtime MSI still owns a target snapshot ACL row.'

    $runtimeLaunchRows = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'LaunchCondition')
    $runtimeMsiConditions = @($runtimeLaunchRows.Condition)
    Assert-Contract ($runtimeMsiConditions -contains 'NOT (Installed AND REMOVE~="ALL" AND DF_ACTIVE_LEASE_FILE)' -and $runtimeMsiConditions -contains 'ACTION = "ADMIN" OR Installed OR NOT DF_ACTIVE_LEASE_FILE') 'Runtime MSI database lacks active removal/upgrade guards.'
    Assert-Contract (@($runtimeMsiConditions | Where-Object { $_ -match 'ACTION = "ADMIN"' -and $_ -match 'DF_WINDOWS_BUILD >= 22000' -and $_ -match 'DF_WINDOWS_INSTALLATION_TYPE = "Client"' }).Count -eq 1) 'Runtime MSI database lacks the strict Win11 client condition.'
    $runtimeOwnerSidRows = @($runtimeLaunchRows | Where-Object { $runtimeOwnerSidConditions -contains $_.Condition -and $_.Description -match 'same signed-in user' })
    Assert-Contract ($runtimeOwnerSidRows.Count -eq $runtimeOwnerSidConditions.Count -and @($runtimeOwnerSidConditions | Where-Object { $_ -notin $runtimeOwnerSidRows.Condition }).Count -eq 0) 'Runtime MSI database lacks the strict interactive owner-SID launch conditions.'

    $appSearchRows = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'AppSearch')
    Assert-Contract (@($appSearchRows | Where-Object { $_.Property -eq 'DF_ACTIVE_LEASE_FILE' -and $_.Signature_ -eq 'FindActiveLeaseFile' }).Count -eq 1) 'Runtime MSI does not search for active-lease.json.'
    $directorySearchRows = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'DrLocator')
    Assert-Contract (@($directorySearchRows | Where-Object { $_.Signature_ -eq 'FindRuntimeDataDirectory' -and $_.Path -eq '[CommonAppDataFolder]DistractionFirewall\Runtime\v1' -and $_.Depth -eq '0' }).Count -eq 1) 'Active marker search is not pinned to the fixed Runtime v1 data root.'
    $registrySearchRows = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'RegLocator')
    Assert-Contract (@($registrySearchRows | Where-Object { $_.Signature_ -eq 'FindRuntimeDataRoot' -and $_.Root -eq '2' -and $_.Key -eq 'SOFTWARE\Motoki0705\DistractionFirewall\Runtime' -and $_.Name -eq 'DataRoot' }).Count -eq 1) 'Cleanup root is not loaded from the 64-bit installer-owned registry seed.'

    $customActions = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'CustomAction')
    Assert-Contract (@($customActions | Where-Object { $_.Action -eq 'SetDfRuntimeDataRoot' -and $_.Source -eq 'DfRuntimeDataRoot' -and $_.Target -eq '[DF_RUNTIME_DATA_ROOT_FROM_REGISTRY]' }).Count -eq 1) 'Cleanup target is not copied into the private property.'
    Assert-Contract (@($customActions | Where-Object { $_.Action -eq 'Wix4RemoveFoldersEx_X64' }).Count -eq 1) 'x64 RemoveFolderEx custom action is missing.'
    Assert-Contract (@($customActions | Where-Object { $_.Action -eq 'GuardRuntimeMutation' -and $_.Type -eq '3090' -and $_.Source -eq 'FinalizerExecutable' -and $_.Target -eq 'guard-runtime-uninstall' }).Count -eq 1) 'Runtime mutation guard MSI row is not checked, deferred, no-impersonation, and bound to the installed finalizer.'
    Assert-Contract (@($customActions | Where-Object { $_.Action -eq 'CleanupRuntimeInstallation' -and $_.Type -eq '3090' -and $_.Source -eq 'FinalizerExecutable' -and $_.Target -eq 'cleanup-runtime-installation' }).Count -eq 1) 'Runtime installation cleanup MSI row is not checked, deferred, no-impersonation, and bound to the installed finalizer.'
    $removeFolderRows = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'Wix4RemoveFolderEx')
    Assert-Contract ($removeFolderRows.Count -eq 1 -and $removeFolderRows[0].Component_ -eq 'RuntimeInstallerSeedComponent' -and $removeFolderRows[0].Property -eq 'DfRuntimeDataRoot' -and $removeFolderRows[0].InstallMode -eq '2' -and $removeFolderRows[0].Condition -eq 'NOT DF_ACTIVE_LEASE_FILE') 'Recursive cleanup is not narrowly bound to inactive Runtime uninstall.'
    $executeSequence = @(Get-MsiTableRows -Context $runtimeDatabase -Table 'InstallExecuteSequence')
    $appSearchSequence = [int](@($executeSequence | Where-Object Action -eq 'AppSearch')[0].Sequence)
    $privatePropertySequence = [int](@($executeSequence | Where-Object Action -eq 'SetDfRuntimeDataRoot')[0].Sequence)
    $removeFolderSequence = [int](@($executeSequence | Where-Object Action -eq 'Wix4RemoveFoldersEx_X64')[0].Sequence)
    $costInitializeSequence = [int](@($executeSequence | Where-Object Action -eq 'CostInitialize')[0].Sequence)
    Assert-Contract ($appSearchSequence -lt $privatePropertySequence -and $privatePropertySequence -lt $removeFolderSequence -and $removeFolderSequence -lt $costInitializeSequence) 'Cleanup property/search actions are not safely ordered before CostInitialize.'
    $stopServicesSequence = [int](@($executeSequence | Where-Object Action -eq 'StopServices')[0].Sequence)
    $guardSequenceRow = @($executeSequence | Where-Object Action -eq 'GuardRuntimeMutation')
    $cleanupSequenceRow = @($executeSequence | Where-Object Action -eq 'CleanupRuntimeInstallation')
    $deleteServicesSequence = [int](@($executeSequence | Where-Object Action -eq 'DeleteServices')[0].Sequence)
    $removeFilesSequence = [int](@($executeSequence | Where-Object Action -eq 'RemoveFiles')[0].Sequence)
    Assert-Contract ($guardSequenceRow.Count -eq 1 -and $guardSequenceRow[0].Condition -eq 'Installed AND (REMOVE~="ALL" OR REINSTALL OR PATCH)') 'Runtime mutation guard execute-sequence condition is missing or too broad.'
    Assert-Contract ($cleanupSequenceRow.Count -eq 1 -and $cleanupSequenceRow[0].Condition -eq 'Installed AND REMOVE~="ALL"') 'Runtime installation cleanup execute-sequence condition is missing or too broad.'
    $guardSequence = [int]$guardSequenceRow[0].Sequence
    $cleanupSequence = [int]$cleanupSequenceRow[0].Sequence
    Assert-Contract ($stopServicesSequence -lt $guardSequence -and $guardSequence -lt $cleanupSequence -and $cleanupSequence -lt $deleteServicesSequence -and $deleteServicesSequence -lt $removeFilesSequence) 'Runtime guard and owned-object cleanup must run after StopServices and before DeleteServices/RemoveFiles.'
}
finally {
    Close-MsiDatabase -Context $runtimeDatabase
    Close-MsiDatabase -Context $appDatabase
}

Assert-Contract ((Get-PeMachine -Path $setupExe) -eq 0x8664) 'Burn setup executable is not AMD64.'

$standaloneHashesBeforeAdministrativeImage = @{
    App = (Get-FileHash -LiteralPath $appMsi -Algorithm SHA256).Hash
    Runtime = (Get-FileHash -LiteralPath $runtimeMsi -Algorithm SHA256).Hash
}
$verificationRoot = Join-Path ([System.IO.Path]::GetTempPath()) "distraction-firewall-installer-verify-$([Guid]::NewGuid().ToString('N'))"
try {
    $null = New-Item -ItemType Directory -Path $verificationRoot
    # An administrative install is permitted to rewrite the MSI database it
    # consumes. Always operate on private copies so verification cannot mutate
    # the release artifacts that will subsequently be hashed and uploaded.
    $administrativeSources = Join-Path $verificationRoot 'administrative-sources'
    $null = New-Item -ItemType Directory -Path $administrativeSources
    $administrativeAppMsi = Join-Path $administrativeSources 'app.msi'
    $administrativeRuntimeMsi = Join-Path $administrativeSources 'runtime.msi'
    Copy-Item -LiteralPath $appMsi -Destination $administrativeAppMsi
    Copy-Item -LiteralPath $runtimeMsi -Destination $administrativeRuntimeMsi
    $appImage = Join-Path $verificationRoot 'app-admin-image'
    $runtimeImage = Join-Path $verificationRoot 'runtime-admin-image'
    Invoke-MsiAdministrativeImage -MsiPath $administrativeAppMsi -Destination $appImage -LogPath (Join-Path $verificationRoot 'app-admin-image.log')
    Invoke-MsiAdministrativeImage -MsiPath $administrativeRuntimeMsi -Destination $runtimeImage -LogPath (Join-Path $verificationRoot 'runtime-admin-image.log')

    $appImageFiles = @(Get-ChildItem -LiteralPath $appImage -File -Recurse)
    $runtimeImageFiles = @(Get-ChildItem -LiteralPath $runtimeImage -File -Recurse)
    $appEntry = @($appImageFiles | Where-Object { $_.Name -eq 'distraction-firewall.exe' -and $_.FullName -match '\\Distraction Firewall\\app\\distraction-firewall\.exe$' })
    $cliEntry = @($appImageFiles | Where-Object { $_.Name -eq 'distraction-firewall-cli.exe' -and $_.FullName -match '\\Distraction Firewall\\cli\\distraction-firewall-cli\.exe$' })
    Assert-Contract ($appEntry.Count -eq 1 -and $cliEntry.Count -eq 1) 'App administrative image does not preserve the app/cli layout.'
    Assert-SelfContainedEntryPoint -EntryPoint $appEntry[0].FullName
    Assert-SelfContainedEntryPoint -EntryPoint $cliEntry[0].FullName
    Assert-Contract (@($appImageFiles | Where-Object { $_.FullName -match '\\Distraction Firewall Lease Runtime\\' -or $_.Name -eq 'distraction-firewall-activation-service.exe' }).Count -eq 0) 'App administrative image contains Runtime-owned payload.'

    $runtimeEntries = [ordered]@{
        'activation-service' = 'distraction-firewall-activation-service.exe'
        'lease-worker' = 'distraction-firewall-lease-worker.exe'
        'dns-filter' = 'distraction-firewall-dns.exe'
        'finalizer' = 'distraction-firewall-finalizer.exe'
    }
    foreach ($componentName in $runtimeEntries.Keys) {
        $fileName = $runtimeEntries[$componentName]
        $entry = @($runtimeImageFiles | Where-Object { $_.Name -eq $fileName -and $_.FullName -match "\\Distraction Firewall Lease Runtime\\$([regex]::Escape($componentName))\\$([regex]::Escape($fileName))$" })
        Assert-Contract ($entry.Count -eq 1) "Runtime administrative image entry point is missing or misplaced: $fileName"
        Assert-SelfContainedEntryPoint -EntryPoint $entry[0].FullName
    }
    Assert-Contract (@($runtimeImageFiles | Where-Object { $_.FullName -match '\\Distraction Firewall\\app\\' -or $_.Name -eq 'distraction-firewall.exe' }).Count -eq 0) 'Runtime administrative image contains App-owned payload.'
    Assert-Contract (@($runtimeImageFiles | Where-Object Name -eq 'target-snapshot.json').Count -eq 0) 'Runtime administrative image improperly contains target-snapshot.json.'
    $observedFiles = @($runtimeImageFiles | Where-Object Name -eq 'observed-addresses.json')
    Assert-Contract ($observedFiles.Count -eq 1) 'Runtime administrative image must contain exactly one observed-addresses.json fixture.'
    $observed = Get-Content -LiteralPath $observedFiles[0].FullName -Raw | ConvertFrom-Json
    Assert-Contract ($observed.schema_version -eq 1 -and @($observed.observations).Count -eq 0) 'Administrative image observed-addresses fixture is malformed.'
    $targetCatalog = @($runtimeImageFiles | Where-Object { $_.Name -eq 'youtube.json' -and $_.FullName -match '\\activation-service\\config\\targets\\youtube\.json$' })
    Assert-Contract ($targetCatalog.Count -eq 1) 'Runtime administrative image lacks the activation-service target catalog.'
    Assert-Contract (@($appImageFiles + $runtimeImageFiles | Where-Object Extension -eq '.pdb').Count -eq 0) 'Administrative images contain PDB files.'

    $bundleExtraction = Join-Path $verificationRoot 'bundle-extraction'
    Invoke-BundleExtraction `
        -SetupPath $setupExe `
        -Destination $bundleExtraction `
        -IntermediateDirectory (Join-Path $verificationRoot 'bundle-extraction-intermediate') `
        -LogPath (Join-Path $verificationRoot 'bundle-extraction.log')
    $extractedPayloads = @(Get-ChildItem -LiteralPath $bundleExtraction -File -Recurse)
    Assert-Contract ($extractedPayloads.Count -eq 2) 'Burn attached container must contain exactly the App and Runtime MSI payloads.'
    $expectedMsiHashes = @(
        $standaloneHashesBeforeAdministrativeImage.App
        $standaloneHashesBeforeAdministrativeImage.Runtime
    ) | Sort-Object
    $extractedHashes = @($extractedPayloads | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }) | Sort-Object
    Assert-Contract (($expectedMsiHashes -join ',') -eq ($extractedHashes -join ',')) 'Burn-attached MSI hashes differ from the standalone App and Runtime MSIs.'
    Assert-Contract ((Get-FileHash -LiteralPath $appMsi -Algorithm SHA256).Hash -eq $standaloneHashesBeforeAdministrativeImage.App) 'Installer verification mutated the standalone App MSI.'
    Assert-Contract ((Get-FileHash -LiteralPath $runtimeMsi -Algorithm SHA256).Hash -eq $standaloneHashesBeforeAdministrativeImage.Runtime) 'Installer verification mutated the standalone Runtime MSI.'
}
finally {
    Remove-VerifiedTemporaryTree -Path $verificationRoot
}

if ($RequireSigning) {
    foreach ($artifact in $expectedArtifacts) {
        $signature = Get-AuthenticodeSignature -LiteralPath $artifact
        Assert-Contract ($signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid) "A valid Authenticode signature is required for $artifact (status: $($signature.Status))."
    }
}

Write-Host "Verified installer source, MSI tables, administrative images, and Burn attached payloads for $Version."
