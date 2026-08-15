[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Version,

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$PublishRoot = 'artifacts/publish',

    [string]$OutputDirectory = 'artifacts/package',

    [switch]$SigningConfigured,

    [string]$SigningCertificateThumbprint = $env:DF_SIGNING_CERTIFICATE_THUMBPRINT,

    [string]$TimestampUrl = $env:DF_SIGNING_TIMESTAMP_URL
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))

function Resolve-RepositoryPath {
    param([Parameter(Mandatory)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $Path))
}

function Invoke-DotNet {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Description
    )

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Resolve-SignTool {
    $command = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
        throw 'signtool.exe was not found and ProgramFiles(x86) is unavailable.'
    }

    $windowsKitBin = Join-Path $programFilesX86 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $windowsKitBin -PathType Container)) {
        throw "signtool.exe was not found below $windowsKitBin."
    }

    $candidates = @(
        Get-ChildItem -LiteralPath $windowsKitBin -Directory |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Sort-Object -Descending
    )

    if ($candidates.Count -eq 0) {
        throw "signtool.exe was not found below $windowsKitBin."
    }

    return $candidates[0]
}

function Invoke-SignFile {
    param(
        [Parameter(Mandatory)][string]$SignTool,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$TimestampServer
    )

    & $SignTool sign /fd SHA256 /sha1 $Thumbprint /tr $TimestampServer /td SHA256 $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode signing failed for $Path with exit code $LASTEXITCODE."
    }

    & $SignTool verify /pa /all $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode verification failed for $Path with exit code $LASTEXITCODE."
    }
}

$semanticVersionPattern = '^(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?<prerelease>(?:0|[1-9]\d*|[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[A-Za-z-][0-9A-Za-z-]*))*))?$'
$versionMatch = [regex]::Match($Version, $semanticVersionPattern)
if (-not $versionMatch.Success) {
    throw "Version must be SemVer without build metadata, for example 0.1.0-alpha.1 or 1.0.0: $Version"
}

$major = [uint64]::Parse($versionMatch.Groups['major'].Value)
$minor = [uint64]::Parse($versionMatch.Groups['minor'].Value)
$patch = [uint64]::Parse($versionMatch.Groups['patch'].Value)
if ($major -gt 255 -or $minor -gt 255 -or $patch -gt 65535) {
    throw "MSI version fields exceed Windows Installer limits (255.255.65535): $Version"
}

$msiVersion = "$major.$minor.$patch"
$isStable = -not $versionMatch.Groups['prerelease'].Success

$statusPath = Join-Path $repositoryRoot 'installer\deferred-active-uninstall.status.json'
if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
    throw "Deferred active uninstall status is missing: $statusPath"
}

$deferredStatus = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
if ($deferredStatus.capability -ne 'deferred-active-uninstall' -or $deferredStatus.implemented -isnot [bool]) {
    throw "Deferred active uninstall status is malformed: $statusPath"
}

$preflightBlockers = [System.Collections.Generic.List[string]]::new()
if ($isStable -and -not $SigningConfigured) {
    $preflightBlockers.Add('Authenticode signing is not configured for a stable version.')
}
if ($isStable -and -not $deferredStatus.implemented) {
    $preflightBlockers.Add('Deferred active uninstall is not implemented and verified for a stable version.')
}
if ($preflightBlockers.Count -gt 0) {
    throw "Packaging preflight is fail-closed:$([Environment]::NewLine)- $($preflightBlockers -join "$([Environment]::NewLine)- ")"
}

if ($deferredStatus.implemented -and @($deferredStatus.evidence).Count -eq 0) {
    throw 'Deferred active uninstall is marked implemented without any verification evidence.'
}

$normalizedThumbprint = $SigningCertificateThumbprint -replace '\s', ''
if ($SigningConfigured) {
    if ($normalizedThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
        throw 'DF_SIGNING_CERTIFICATE_THUMBPRINT must be a 40-character SHA-1 certificate thumbprint when signing is configured.'
    }

    $timestampUri = $null
    if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or $timestampUri.Scheme -ne 'https') {
        throw 'DF_SIGNING_TIMESTAMP_URL must be an absolute HTTPS URL when signing is configured.'
    }
}

$publishRootPath = Resolve-RepositoryPath $PublishRoot
$outputPath = Resolve-RepositoryPath $OutputDirectory

$publishInputs = @(
    [pscustomobject]@{ Project = 'DistractionFirewall.App'; PrimaryFile = 'distraction-firewall.exe'; SelfContained = $true },
    [pscustomobject]@{ Project = 'DistractionFirewall.Cli'; PrimaryFile = 'distraction-firewall-cli.exe'; SelfContained = $true },
    [pscustomobject]@{ Project = 'DistractionFirewall.ActivationService'; PrimaryFile = 'distraction-firewall-activation-service.exe'; SelfContained = $true },
    [pscustomobject]@{ Project = 'DistractionFirewall.LeaseWorker'; PrimaryFile = 'distraction-firewall-lease-worker.exe'; SelfContained = $true },
    [pscustomobject]@{ Project = 'DistractionFirewall.DnsFilter'; PrimaryFile = 'distraction-firewall-dns.exe'; SelfContained = $true },
    [pscustomobject]@{ Project = 'DistractionFirewall.Finalizer'; PrimaryFile = 'distraction-firewall-finalizer.exe'; SelfContained = $true },
    [pscustomobject]@{ Project = 'DistractionFirewall.Enforcement.Windows'; PrimaryFile = 'DistractionFirewall.Enforcement.Windows.dll'; SelfContained = $false }
)

$publishDirectories = @{}
foreach ($input in $publishInputs) {
    $directory = Join-Path $publishRootPath "$($input.Project)\win-x64"
    $primaryFile = Join-Path $directory $input.PrimaryFile
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Publish input directory is missing: $directory"
    }
    if (-not (Test-Path -LiteralPath $primaryFile -PathType Leaf)) {
        throw "Expected publish entry point is missing: $primaryFile"
    }
    if (@(Get-ChildItem -LiteralPath $directory -File -Recurse).Count -eq 0) {
        throw "Publish input directory is empty: $directory"
    }
    if ($input.SelfContained) {
        $entryPointBaseName = [System.IO.Path]::GetFileNameWithoutExtension($input.PrimaryFile)
        $requiredSelfContainedFiles = @(
            "$entryPointBaseName.runtimeconfig.json",
            'coreclr.dll',
            'hostfxr.dll',
            'hostpolicy.dll'
        )
        foreach ($requiredFile in $requiredSelfContainedFiles) {
            $requiredPath = Join-Path $directory $requiredFile
            if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
                throw "Self-contained win-x64 publish input is incomplete: $requiredPath"
            }
        }
    }
    $publishDirectories[$input.Project] = $directory
}

$null = New-Item -ItemType Directory -Path $outputPath -Force

$appBaseName = "distraction-firewall-app-$Version-win-x64"
$runtimeBaseName = "distraction-firewall-runtime-$Version-win-x64"
$bundleBaseName = "distraction-firewall-setup-$Version-win-x64"
$appMsi = Join-Path $outputPath "$appBaseName.msi"
$runtimeMsi = Join-Path $outputPath "$runtimeBaseName.msi"
$setupExe = Join-Path $outputPath "$bundleBaseName.exe"

foreach ($target in @($appMsi, $runtimeMsi, $setupExe)) {
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        Remove-Item -LiteralPath $target -Force
    }
}

$appProject = Join-Path $repositoryRoot 'installer\App\DistractionFirewall.App.Installer.wixproj'
$runtimeProject = Join-Path $repositoryRoot 'installer\Runtime\DistractionFirewall.Runtime.Installer.wixproj'
$bundleProject = Join-Path $repositoryRoot 'installer\Bundle\DistractionFirewall.Bundle.wixproj'

foreach ($project in @($appProject, $runtimeProject, $bundleProject)) {
    Invoke-DotNet -Description "Locked restore for $project" -Arguments @(
        'restore', $project, '--locked-mode', '--nologo'
    )
}

$commonBuildArguments = @(
    '--configuration', $Configuration,
    '--no-restore',
    '--no-incremental',
    '--nologo',
    '-p:ContinuousIntegrationBuild=true',
    "-p:OutputPath=$outputPath\",
    "-p:MsiVersion=$msiVersion",
    "-p:PackageSemanticVersion=$Version",
    "-p:RequireDeferredActiveUninstall=$($isStable.ToString().ToLowerInvariant())"
)

Invoke-DotNet -Description 'App MSI build' -Arguments (@(
    'build', $appProject
    ) + $commonBuildArguments + @(
        "-p:OutputName=$appBaseName",
        "-p:AppPublishDir=$($publishDirectories['DistractionFirewall.App'])",
        "-p:CliPublishDir=$($publishDirectories['DistractionFirewall.Cli'])"
    ))

Invoke-DotNet -Description 'Runtime MSI build' -Arguments (@(
    'build', $runtimeProject
    ) + $commonBuildArguments + @(
        "-p:OutputName=$runtimeBaseName",
        "-p:ActivationServicePublishDir=$($publishDirectories['DistractionFirewall.ActivationService'])",
        "-p:LeaseWorkerPublishDir=$($publishDirectories['DistractionFirewall.LeaseWorker'])",
        "-p:DnsFilterPublishDir=$($publishDirectories['DistractionFirewall.DnsFilter'])",
        "-p:FinalizerPublishDir=$($publishDirectories['DistractionFirewall.Finalizer'])",
        "-p:EnforcementPublishDir=$($publishDirectories['DistractionFirewall.Enforcement.Windows'])"
    ))

if ($SigningConfigured) {
    $signTool = Resolve-SignTool
    Invoke-SignFile -SignTool $signTool -Path $appMsi -Thumbprint $normalizedThumbprint -TimestampServer $TimestampUrl
    Invoke-SignFile -SignTool $signTool -Path $runtimeMsi -Thumbprint $normalizedThumbprint -TimestampServer $TimestampUrl
}

Invoke-DotNet -Description 'Burn setup build' -Arguments (@(
    'build', $bundleProject
    ) + $commonBuildArguments + @(
        "-p:OutputName=$bundleBaseName",
        "-p:PackageOutputPath=$outputPath\",
        "-p:AppMsiFileName=$([System.IO.Path]::GetFileName($appMsi))",
        "-p:RuntimeMsiFileName=$([System.IO.Path]::GetFileName($runtimeMsi))"
    ))

if ($SigningConfigured) {
    Invoke-SignFile -SignTool $signTool -Path $setupExe -Thumbprint $normalizedThumbprint -TimestampServer $TimestampUrl
}

$verifyArguments = @{
    Version = $Version
    PackageDirectory = $outputPath
}
if ($SigningConfigured) {
    $verifyArguments.RequireSigning = $true
}
if ($isStable) {
    $verifyArguments.RequireDeferredActiveUninstall = $true
}

& (Join-Path $PSScriptRoot 'verify-installer.ps1') @verifyArguments

Write-Host "Packaged $Version to $outputPath"
