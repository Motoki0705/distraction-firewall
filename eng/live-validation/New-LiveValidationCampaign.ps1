#requires -Version 5.1

<#+
.SYNOPSIS
Creates a candidate-specific, single-UAC Windows 11 live-validation campaign.

.DESCRIPTION
This command is deliberately non-elevated. It validates a build-once package,
its external GitHub Actions provenance envelope, and an optional exact Runtime
recovery MSI. It then emits a single-use parent/child campaign whose paths,
hashes, MSI identities, owner SID, and phase nonce are embedded.

The generated parent remains in the caller's standard token. Only the fixed
MSI/service phase is elevated once. The parent performs the CLI and UI smoke so
those clients never inherit the elevated token.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateManifestPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ProvenanceEnvelopePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PackageDirectory,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateArchivePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [string]$RecoveryManifestPath,

    [string]$RecoveryPackageDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$nativeSystemDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::System)).TrimEnd('\')
$nativeWindowsDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)).TrimEnd('\')
$trustedPowerShellHome = [IO.Path]::GetFullPath([IO.Path]::Combine($nativeSystemDirectory, 'WindowsPowerShell', 'v1.0')).TrimEnd('\')
if (-not ([IO.Path]::GetFullPath($PSHOME).TrimEnd('\').Equals($trustedPowerShellHome, [StringComparison]::OrdinalIgnoreCase))) {
    throw 'Campaign generation must run in native Windows PowerShell 5.1.'
}
$trustedPowerShellModuleRoot = [IO.Path]::Combine($trustedPowerShellHome, 'Modules')
$env:PATH = "$nativeSystemDirectory;$nativeWindowsDirectory;$trustedPowerShellHome"
$env:PSModulePath = $trustedPowerShellModuleRoot
$env:PATHEXT = '.COM;.EXE;.BAT;.CMD'
foreach ($moduleName in @('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security')) {
    $moduleManifest = [IO.Path]::Combine($trustedPowerShellModuleRoot, $moduleName, "$moduleName.psd1")
    Microsoft.PowerShell.Core\Import-Module -Name $moduleManifest -Force -ErrorAction Stop
}
$PSModuleAutoLoadingPreference = 'None'

$fixed = [ordered]@{
    Repository = 'Motoki0705/distraction-firewall'
    BundleUpgradeCode = '{9F89BB92-BF79-4127-A4F5-4A4A4FD88EE6}'
    AppUpgradeCode = '{F6467493-5819-4046-900A-C9FDF87DF7C1}'
    RuntimeUpgradeCode = '{275EC377-2EB2-487F-AD4B-BA0BA85C2FFB}'
    ServiceName = 'DistractionFirewallActivation'
    ProductInstanceId = 'Motoki0705.DistractionFirewall.Runtime.v1'
}

# Recovery is intentionally incident-specific. This is a code-owned allowlist,
# not authority delegated to a caller-supplied manifest. Any future incident
# must receive a reviewed code/schema change before its MSI can cross UAC.
$approvedRecovery = [ordered]@{
    ManifestSha256 = '29962be5b7992ac17b13ac4aaa0c46320c5a5b4fba481e3b1e46a36bad9366e2'
    IncidentId = 'pretag-alpha2-runtime-uninstall-1603'
    Mode = 'repair_then_uninstall'
    RuntimeMsi = [ordered]@{
        fileName = 'distraction-firewall-runtime-recovery-1b676614-win-x64.msi'
        size = [int64]86290721
        sha256 = 'ef35d8ccb1a110f70dd4f6a9989bbc2b30a0b2b467b4fdc380ce6973b83c50da'
        authenticodeStatus = 'NotSigned'
        productCode = '{1B676614-3B1F-4646-9788-889C071DAAA0}'
        packageCode = '{AD62973E-B6B1-49B6-961B-C3688C7B9C26}'
        upgradeCode = '{275EC377-2EB2-487F-AD4B-BA0BA85C2FFB}'
        productVersion = '0.1.0'
    }
    ExpectedInstalled = [ordered]@{
        productCode = '{1B676614-3B1F-4646-9788-889C071DAAA0}'
        packageCode = '{11A25941-6631-4793-8AD7-753985510F77}'
        productVersion = '0.1.0'
        localPackage = [ordered]@{
            sizeBytes = [int64]86282518
            sha256 = 'b9a94e0a2dbdc40ba3b0996fc5a304bf153d1e3e30ef8e0e7d420844bd300dfe'
        }
    }
    OrphanBundleProviderKeys = @('{247145F8-425B-46EA-B22F-560F2EE43DAE}')
    OrphanPackageCaches = @(
        [ordered]@{
            directoryName = '{40C25BD0-2C4F-4697-AE8D-42B6E24EBB41}v0.1.0'
            dependencyProviderKey = '{40C25BD0-2C4F-4697-AE8D-42B6E24EBB41}_v0.1.0'
            productCode = '{40C25BD0-2C4F-4697-AE8D-42B6E24EBB41}'
            packageCode = '{85C80D60-7836-4F20-AC4D-EBB62CF7E663}'
            upgradeCode = '{F6467493-5819-4046-900A-C9FDF87DF7C1}'
            productVersion = '0.1.0'
            payload = [ordered]@{
                fileName = 'distraction-firewall-app-0.1.0-alpha.2-win-x64.msi'
                sizeBytes = [int64]78274808
                sha256 = '9a41cb076aceae9aede9028b7410c15a84150416c3fe657b7e6daff31bc2cc17'
            }
        },
        [ordered]@{
            directoryName = '{1B676614-3B1F-4646-9788-889C071DAAA0}v0.1.0'
            dependencyProviderKey = '{1B676614-3B1F-4646-9788-889C071DAAA0}_v0.1.0'
            productCode = '{1B676614-3B1F-4646-9788-889C071DAAA0}'
            packageCode = '{11A25941-6631-4793-8AD7-753985510F77}'
            upgradeCode = '{275EC377-2EB2-487F-AD4B-BA0BA85C2FFB}'
            productVersion = '0.1.0'
            payload = [ordered]@{
                fileName = 'distraction-firewall-runtime-0.1.0-alpha.2-win-x64.msi'
                sizeBytes = [int64]86282518
                sha256 = 'b9a94e0a2dbdc40ba3b0996fc5a304bf153d1e3e30ef8e0e7d420844bd300dfe'
            }
        }
    )
}

function Assert-Condition {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Resolve-ExistingLeaf {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-Condition (Test-Path -LiteralPath $fullPath -PathType Leaf) "$Description is missing: $fullPath"
    $item = Get-Item -LiteralPath $fullPath -Force
    Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Description must not be a reparse point: $fullPath"
    return $item
}

function Resolve-ExistingDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-Condition (Test-Path -LiteralPath $fullPath -PathType Container) "$Description is missing: $fullPath"
    $item = Get-Item -LiteralPath $fullPath -Force
    Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Description must not be a reparse point: $fullPath"
    return $item
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Required,
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string]$Description
    )

    $names = @($Value.PSObject.Properties.Name)
    foreach ($name in $Required) {
        Assert-Condition ($names -ccontains $name) "$Description is missing '$name'."
    }
    foreach ($name in $names) {
        Assert-Condition ($Allowed -ccontains $name) "$Description contains unsupported property '$name'."
    }
}

function Assert-CanonicalGuid {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-Condition ($Value -cmatch '^\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}$') "$Description is not a canonical uppercase braced GUID."
}

function Assert-HexSha256 {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-Condition ($Value -cmatch '^[0-9a-f]{64}$') "$Description is not lowercase SHA-256."
}

function Get-LowerSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if ($null -eq ('DistractionFirewall.LiveValidation.MandatoryIntegrityInspection' -as [type])) {
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DistractionFirewall.LiveValidation
{
    public static class MandatoryIntegrityInspection
    {
        private const uint SeFileObject = 1;
        private const uint LabelSecurityInformation = 0x00000010;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint GetNamedSecurityInfoW(
            string objectName,
            uint objectType,
            uint securityInformation,
            IntPtr owner,
            IntPtr group,
            IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr securityDescriptor,
            uint requestedRevision,
            uint securityInformation,
            out IntPtr stringSecurityDescriptor,
            out uint stringSecurityDescriptorLength);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static string GetLabelSddl(string path)
        {
            IntPtr sacl;
            IntPtr securityDescriptor;
            uint result = GetNamedSecurityInfoW(
                path,
                SeFileObject,
                LabelSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out sacl,
                out securityDescriptor);
            if (result != 0)
            {
                throw new Win32Exception((int)result);
            }

            try
            {
                IntPtr text;
                uint textLength;
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    securityDescriptor,
                    1,
                    LabelSecurityInformation,
                    out text,
                    out textLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                try
                {
                    return Marshal.PtrToStringUni(text) ?? string.Empty;
                }
                finally
                {
                    LocalFree(text);
                }
            }
            finally
            {
                LocalFree(securityDescriptor);
            }
        }
    }
}
'@
}

function Assert-AcceptableMandatoryIntegritySddl {
    param(
        [AllowEmptyString()][Parameter(Mandatory)][string]$Sddl,
        [Parameter(Mandatory)][string]$Description
    )

    # LABEL_SECURITY_INFORMATION returns an empty string when no explicit label
    # exists. Windows then applies the effective Medium object integrity level.
    if ([string]::IsNullOrEmpty($Sddl)) { return }
    try { $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl) }
    catch { throw "$Description mandatory integrity label could not be parsed." }
    $mandatoryAces = @()
    if ($null -ne $descriptor.SystemAcl) {
        for ($index = 0; $index -lt $descriptor.SystemAcl.Count; $index++) {
            $ace = $descriptor.SystemAcl[$index]
            if ([int]$ace.AceType -eq 17) { $mandatoryAces += $ace }
        }
    }
    if ($mandatoryAces.Count -eq 0) { return }
    Assert-Condition ($mandatoryAces.Count -eq 1) "$Description has a conflicting mandatory integrity label set."
    $binary = New-Object byte[] $mandatoryAces[0].BinaryLength
    $mandatoryAces[0].GetBinaryForm($binary, 0)
    Assert-Condition ($binary.Length -ge 20) "$Description mandatory integrity label is malformed."
    $policyMask = [BitConverter]::ToUInt32($binary, 4)
    Assert-Condition ($policyMask -in @([uint32]1, [uint32]3, [uint32]5, [uint32]7)) "$Description mandatory integrity policy is unknown or permits write-up."
    try { $labelSid = [Security.Principal.SecurityIdentifier]::new($binary, 8) }
    catch { throw "$Description mandatory integrity SID could not be parsed." }
    Assert-Condition ($binary.Length -eq (8 + $labelSid.BinaryLength)) "$Description mandatory integrity label has trailing data."
    Assert-Condition ($labelSid.Value -in @('S-1-16-8192', 'S-1-16-12288', 'S-1-16-16384')) "$Description has an untrusted, low, or unknown mandatory integrity level: $($labelSid.Value)"
}

function Assert-TrustedGitHubCliPathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $item = Get-Item -LiteralPath $Path -Force
    Assert-Condition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Description is a reparse point."
    Assert-AcceptableMandatoryIntegritySddl ([DistractionFirewall.LiveValidation.MandatoryIntegrityInspection]::GetLabelSddl($item.FullName)) $Description
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $privilegedSids = @('S-1-5-18', 'S-1-5-32-544', $trustedInstaller)
    Assert-Condition ($owner -in $privilegedSids) "$Description owner is not SYSTEM, Administrators, or TrustedInstaller: $owner"

    # WriteData/CreateFiles, AppendData/CreateDirectories, write EA/attributes,
    # delete, ACL/owner changes, plus generic write/all. Do not OR composite
    # FullControl/Modify values: those include read/synchronize bits and would
    # falsely classify an ordinary ReadAndExecute ACE as writable.
    $dangerousRightsMask = [int64]0x500D0156
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
    for ($index = 0; $index -lt $descriptor.DiscretionaryAcl.Count; $index++) {
        $ace = $descriptor.DiscretionaryAcl[$index]
        if ($ace -isnot [Security.AccessControl.QualifiedAce] -or $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
        if (([int]$ace.AceFlags -band [int][Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
        $sid = $ace.SecurityIdentifier.Value
        $rawRights = [int64][int32]$ace.AccessMask
        if ($rawRights -lt 0) { $rawRights += 4294967296 }
        if (($rawRights -band $dangerousRightsMask) -ne 0) {
            Assert-Condition ($sid -in $privilegedSids) "$Description grants write/delete/ACL rights to non-privileged SID $sid."
        }
    }
}

function Resolve-TrustedGitHubCli {
    $programFilesValue = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($programFilesValue)) 'Native Program Files could not be resolved.'
    $programFiles = [IO.Path]::GetFullPath($programFilesValue).TrimEnd('\')
    $cliDirectory = [IO.Path]::GetFullPath((Join-Path $programFiles 'GitHub CLI')).TrimEnd('\')
    $cliPath = [IO.Path]::GetFullPath((Join-Path $cliDirectory 'gh.exe'))
    Assert-Condition ([IO.Path]::GetDirectoryName($cliDirectory).Equals($programFiles, [StringComparison]::OrdinalIgnoreCase)) 'GitHub CLI directory escaped native Program Files.'
    Assert-Condition ([IO.Path]::GetDirectoryName($cliPath).Equals($cliDirectory, [StringComparison]::OrdinalIgnoreCase)) 'GitHub CLI executable escaped its fixed directory.'
    Assert-Condition (Test-Path -LiteralPath $programFiles -PathType Container) 'Native Program Files is missing.'
    Assert-Condition (Test-Path -LiteralPath $cliDirectory -PathType Container) 'GitHub CLI must be installed in native Program Files.'
    Assert-Condition (Test-Path -LiteralPath $cliPath -PathType Leaf) 'Fixed GitHub CLI executable is missing.'
    Assert-TrustedGitHubCliPathAcl $programFiles 'native Program Files'
    Assert-TrustedGitHubCliPathAcl $cliDirectory 'GitHub CLI directory'
    Assert-TrustedGitHubCliPathAcl $cliPath 'GitHub CLI executable'

    $signature = Get-AuthenticodeSignature -LiteralPath $cliPath
    $expectedSubject = 'CN="GitHub, Inc.", O="GitHub, Inc.", L=San Francisco, S=California, C=US'
    Assert-Condition ($signature.Status.ToString() -ceq 'Valid' -and $null -ne $signature.SignerCertificate) 'GitHub CLI Authenticode signature is not valid.'
    Assert-Condition ([string]$signature.SignerCertificate.Subject -ceq $expectedSubject) 'GitHub CLI publisher is not GitHub, Inc.'
    $versionOutput = @(& $cliPath --version 2>&1)
    Assert-Condition ($LASTEXITCODE -eq 0 -and $versionOutput.Count -ge 1 -and [string]$versionOutput[0] -cmatch '^gh version ([0-9]+\.[0-9]+\.[0-9]+) \(') 'GitHub CLI version output is malformed.'
    $version = $Matches[1]
    $item = Get-Item -LiteralPath $cliPath -Force
    return [pscustomobject][ordered]@{
        path = $item.FullName
        size = [int64]$item.Length
        sha256 = Get-LowerSha256 $item.FullName
        version = $version
        authenticode_status = 'Valid'
        signer_subject = [string]$signature.SignerCertificate.Subject
        signer_thumbprint = [string]$signature.SignerCertificate.Thumbprint
    }
}

function Invoke-TrustedGitHubCli {
    param(
        [Parameter(Mandatory)]$TrustedGitHubCli,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$Token,
        [switch]$UseUserAuthenticationConfig
    )

    $scopedNames = @(
        'GH_HOST', 'GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN', 'GHE_HOST',
        'GH_CONFIG_DIR', 'XDG_CONFIG_HOME', 'GH_PAGER', 'PAGER', 'GH_FORCE_TTY', 'GH_PROMPT_DISABLED',
        'GH_DEBUG', 'GH_BROWSER', 'BROWSER', 'GH_EDITOR', 'GIT_EDITOR', 'VISUAL', 'EDITOR', 'GH_PATH',
        'GH_NO_UPDATE_NOTIFIER', 'NO_COLOR', 'CLICOLOR'
    )
    $saved = @{}
    foreach ($name in $scopedNames) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $isolatedConfigDirectory = $null
    try {
        if ($UseUserAuthenticationConfig) {
            $applicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
            Assert-Condition (-not [string]::IsNullOrWhiteSpace($applicationData)) 'User application-data directory could not be resolved for GitHub authentication.'
            $configDirectory = [IO.Path]::Combine($applicationData, 'GitHub CLI')
        }
        else {
            Assert-Condition (-not [string]::IsNullOrWhiteSpace($Token)) 'An explicit github.com token is required with isolated GitHub CLI configuration.'
            $isolatedConfigDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), ("distraction-firewall-gh-{0}" -f [Guid]::NewGuid().ToString('N')))
            $configItem = [IO.Directory]::CreateDirectory($isolatedConfigDirectory)
            Assert-Condition (($configItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Isolated GitHub CLI config directory is a reparse point.'
            $configDirectory = $isolatedConfigDirectory
        }
        $env:GH_HOST = 'github.com'
        $env:GH_TOKEN = if ($UseUserAuthenticationConfig) { $null } else { $Token }
        $env:GITHUB_TOKEN = $null
        $env:GH_ENTERPRISE_TOKEN = $null
        $env:GITHUB_ENTERPRISE_TOKEN = $null
        $env:GHE_HOST = $null
        $env:GH_CONFIG_DIR = $configDirectory
        $env:XDG_CONFIG_HOME = $null
        $env:GH_PAGER = $null
        $env:PAGER = $null
        $env:GH_FORCE_TTY = '0'
        $env:GH_PROMPT_DISABLED = '1'
        $env:GH_DEBUG = $null
        $env:GH_BROWSER = $null
        $env:BROWSER = $null
        $env:GH_EDITOR = $null
        $env:GIT_EDITOR = $null
        $env:VISUAL = $null
        $env:EDITOR = $null
        $env:GH_PATH = $null
        $env:GH_NO_UPDATE_NOTIFIER = '1'
        $env:NO_COLOR = '1'
        $env:CLICOLOR = '0'
        $output = @(& $TrustedGitHubCli.path @Arguments 2>&1)
        return [pscustomobject][ordered]@{ exit_code = [int]$LASTEXITCODE; output = @($output) }
    }
    finally {
        foreach ($name in $scopedNames) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
        if ($null -ne $isolatedConfigDirectory -and [IO.Directory]::Exists($isolatedConfigDirectory)) {
            [IO.Directory]::Delete($isolatedConfigDirectory, $true)
        }
    }
}

function Get-GitHubToken {
    param([Parameter(Mandatory)]$TrustedGitHubCli)
    if (-not [string]::IsNullOrWhiteSpace($env:GH_TOKEN)) { return $env:GH_TOKEN }
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) { return $env:GITHUB_TOKEN }
    $call = Invoke-TrustedGitHubCli $TrustedGitHubCli @('auth', 'token', '--hostname', 'github.com') -UseUserAuthenticationConfig
    $token = (@($call.output) -join '').Trim()
    Assert-Condition ($call.exit_code -eq 0 -and -not [string]::IsNullOrWhiteSpace($token)) 'GitHub CLI did not return an authentication token for github.com.'
    return $token
}

function Get-StreamSha256 {
    param([Parameter(Mandatory)][IO.Stream]$Stream)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function Assert-ApprovedRecoveryIncident {
    param(
        [Parameter(Mandatory)]$Recovery,
        [Parameter(Mandatory)][string]$ManifestSha256
    )

    Assert-Condition ($ManifestSha256 -ceq [string]$approvedRecovery.ManifestSha256) 'Recovery manifest is not the code-approved incident manifest.'
    Assert-Condition ([string]$Recovery.incidentId -ceq [string]$approvedRecovery.IncidentId) 'Recovery incident ID is not code-approved.'
    Assert-Condition ([string]$Recovery.mode -ceq [string]$approvedRecovery.Mode) 'Recovery mode is not code-approved.'
    Assert-Condition ($Recovery.approvedForMachineRecovery -is [bool] -and $Recovery.approvedForMachineRecovery) 'Runtime recovery is not explicitly approved.'

    $actualRuntime = $Recovery.runtimeMsi | ConvertTo-Json -Depth 8 -Compress
    $expectedRuntime = $approvedRecovery.RuntimeMsi | ConvertTo-Json -Depth 8 -Compress
    Assert-Condition ($actualRuntime -ceq $expectedRuntime) 'Recovery MSI record is outside the code-approved incident allowlist.'

    $actualInstalled = $Recovery.expectedInstalled | ConvertTo-Json -Depth 8 -Compress
    $expectedInstalled = $approvedRecovery.ExpectedInstalled | ConvertTo-Json -Depth 8 -Compress
    Assert-Condition ($actualInstalled -ceq $expectedInstalled) 'Expected installed Runtime record is outside the code-approved incident allowlist.'

    $actualBundleKeys = @($Recovery.orphanBundleProviderKeys) | ConvertTo-Json -Depth 8 -Compress
    $expectedBundleKeys = @($approvedRecovery.OrphanBundleProviderKeys) | ConvertTo-Json -Depth 8 -Compress
    Assert-Condition ($actualBundleKeys -ceq $expectedBundleKeys) 'Recovery orphan Bundle allowlist differs from the code-approved incident.'

    $actualCaches = @($Recovery.orphanPackageCaches) | ConvertTo-Json -Depth 12 -Compress
    $expectedCaches = @($approvedRecovery.OrphanPackageCaches) | ConvertTo-Json -Depth 12 -Compress
    Assert-Condition ($actualCaches -ceq $expectedCaches) 'Recovery orphan Package Cache allowlist differs from the code-approved incident.'
}

function Assert-ArchiveMatchesExtraction {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$ExtractedDirectory,
        [Parameter(Mandatory)][string[]]$ExpectedNames,
        [Parameter(Mandatory)][hashtable]$ExpectedHashes
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $entryNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $entryHashes = @{}
        foreach ($entry in $archive.Entries) {
            Assert-Condition (-not [string]::IsNullOrEmpty($entry.Name)) 'Artifact archive contains a directory entry.'
            Assert-Condition ([IO.Path]::GetFileName($entry.FullName) -ceq $entry.FullName) "Artifact archive is not flat: $($entry.FullName)"
            Assert-SafeLeafName $entry.FullName 'artifact archive entry'
            Assert-Condition $entryNames.Add($entry.FullName) "Artifact archive contains a duplicate entry: $($entry.FullName)"
            $stream = $entry.Open()
            try { $entryHashes[$entry.FullName] = Get-StreamSha256 $stream }
            finally { $stream.Dispose() }
        }
        $extractedFiles = @(Get-ChildItem -LiteralPath $ExtractedDirectory -File -Force)
        Assert-Condition (@(Get-ChildItem -LiteralPath $ExtractedDirectory -Directory -Force).Count -eq 0) 'Extracted artifact directory must be flat.'
        Assert-Condition (-not [bool](Compare-Object -ReferenceObject @($ExpectedNames | Sort-Object) -DifferenceObject @($entryNames | Sort-Object))) 'Raw artifact archive does not have the exact nine-file inventory.'
        Assert-Condition ($entryNames.Count -eq $extractedFiles.Count) 'Raw archive and extracted directory file counts differ.'
        foreach ($file in $extractedFiles) {
            Assert-Condition $entryNames.Contains($file.Name) "Extracted file is absent from the raw archive: $($file.Name)"
            Assert-Condition ((Get-LowerSha256 $file.FullName) -ceq [string]$entryHashes[$file.Name]) "Extracted file differs from raw archive bytes: $($file.Name)"
        }
        foreach ($name in $ExpectedHashes.Keys) {
            Assert-Condition $entryNames.Contains($name) "Required payload is absent from raw archive: $name"
            Assert-Condition ([string]$entryHashes[$name] -ceq [string]$ExpectedHashes[$name]) "Raw archive payload hash mismatch: $name"
        }
    }
    finally { $archive.Dispose() }
}

function Assert-SafeLeafName {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-Condition (-not [string]::IsNullOrWhiteSpace($Value)) "$Description is empty."
    Assert-Condition ([IO.Path]::GetFileName($Value) -ceq $Value) "$Description must be a leaf filename."
    Assert-Condition ($Value.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -lt 0) "$Description contains an invalid filename character."
}

function Get-MsiIdentity {
    param([Parameter(Mandatory)][string]$Path)

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    try {
        $database = $installer.OpenDatabase($Path, 0)
        $properties = [ordered]@{}
        foreach ($propertyName in @('ProductCode', 'UpgradeCode', 'ProductVersion')) {
            $query = "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$propertyName'"
            $view = $database.OpenView($query)
            try {
                $null = $view.Execute()
                $record = $view.Fetch()
                Assert-Condition ($null -ne $record) "MSI Property '$propertyName' is absent: $Path"
                try {
                    $properties[$propertyName] = [string]$record.StringData(1)
                }
                finally {
                    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
                }
            }
            finally {
                $null = $view.Close()
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
            }
        }

        $summary = $database.SummaryInformation(0)
        try {
            $packageCode = [string]$summary.Property(9)
        }
        finally {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)
        }

        return [pscustomobject][ordered]@{
            product_code = $properties.ProductCode.ToUpperInvariant()
            upgrade_code = $properties.UpgradeCode.ToUpperInvariant()
            product_version = $properties.ProductVersion
            package_code = $packageCode.ToUpperInvariant()
        }
    }
    finally {
        if ($null -ne $database) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
        }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}

function Assert-Artifact {
    param(
        [Parameter(Mandatory)]$Artifact,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Description,
        [switch]$Binary
    )

    Assert-SafeLeafName ([string]$Artifact.fileName) "$Description fileName"
    Assert-HexSha256 ([string]$Artifact.sha256) "$Description sha256"
    $sizeProperty = $Artifact.PSObject.Properties['sizeBytes']
    if ($null -eq $sizeProperty) { $sizeProperty = $Artifact.PSObject.Properties['size'] }
    Assert-Condition ($null -ne $sizeProperty -and [int64]$sizeProperty.Value -gt 0) "$Description size must be positive."
    $rootItem = Resolve-ExistingDirectory -Path $Root -Description "$Description package directory"
    $path = [IO.Path]::GetFullPath((Join-Path $rootItem.FullName ([string]$Artifact.fileName)))
    Assert-Condition ([IO.Path]::GetDirectoryName($path).Equals($rootItem.FullName.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) "$Description escaped its package directory."
    $item = Resolve-ExistingLeaf -Path $path -Description $Description
    Assert-Condition ($item.Length -eq [int64]$sizeProperty.Value) "$Description size mismatch."
    Assert-Condition ((Get-LowerSha256 $item.FullName) -ceq [string]$Artifact.sha256) "$Description SHA-256 mismatch."
    if ($Binary) {
        Assert-Condition ([string]$Artifact.authenticodeStatus -cin @('Valid', 'NotSigned')) "$Description Authenticode expectation must be Valid or NotSigned."
        $status = (Get-AuthenticodeSignature -LiteralPath $item.FullName).Status.ToString()
        Assert-Condition ($status -ceq [string]$Artifact.authenticodeStatus) "$Description Authenticode status mismatch: expected $($Artifact.authenticodeStatus), observed $status."
    }
    return $item.FullName
}

function Convert-ToEmbeddedRecord {
    param([Parameter(Mandatory)]$Value)
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
}

function Get-GitHubApiJson {
    param([Parameter(Mandatory)][string]$Endpoint)
    $call = Invoke-TrustedGitHubCli $trustedGitHubCli @('api', '--hostname', 'github.com', '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28', $Endpoint) -Token $trustedGitHubToken
    Assert-Condition ($call.exit_code -eq 0) "GitHub API metadata query failed: $Endpoint"
    return (@($call.output) -join [Environment]::NewLine) | ConvertFrom-Json
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-Condition (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Preparation must run from the non-elevated owner token.'
Assert-Condition ([Environment]::Is64BitOperatingSystem -and [Environment]::Is64BitProcess) 'Preparation requires native x64 PowerShell on x64 Windows.'
Assert-Condition ($null -ne $identity.User) 'The current Windows identity has no user SID.'
$ownerSid = $identity.User.Value
$unsupportedSids = @('S-1-0-0', 'S-1-1-0', 'S-1-2-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-546')
Assert-Condition ($ownerSid -notin $unsupportedSids) 'The owner SID is a service, broad, or built-in principal.'
$trustedGitHubCli = Resolve-TrustedGitHubCli
$trustedGitHubToken = Get-GitHubToken $trustedGitHubCli

$candidateManifestItem = Resolve-ExistingLeaf -Path $CandidateManifestPath -Description 'candidate manifest'
$provenanceItem = Resolve-ExistingLeaf -Path $ProvenanceEnvelopePath -Description 'provenance envelope'
$candidateArchiveItem = Resolve-ExistingLeaf -Path $CandidateArchivePath -Description 'raw GitHub artifact archive'
Assert-Condition ($candidateArchiveItem.Extension -ceq '.zip') 'Raw GitHub artifact archive must be a .zip file.'
$packageRoot = (Resolve-ExistingDirectory -Path $PackageDirectory -Description 'candidate package directory').FullName
$manifestSha256 = Get-LowerSha256 $candidateManifestItem.FullName
$provenanceSha256 = Get-LowerSha256 $provenanceItem.FullName
$candidate = Get-Content -LiteralPath $candidateManifestItem.FullName -Raw | ConvertFrom-Json
$provenance = Get-Content -LiteralPath $provenanceItem.FullName -Raw | ConvertFrom-Json

Assert-ExactProperties $candidate @('schema', 'version', 'source', 'artifacts', 'signing') @('schema', 'version', 'source', 'artifacts', 'signing') 'candidate manifest'
Assert-Condition ([string]$candidate.schema -ceq 'distraction-firewall/build-once-candidate/v1') 'Candidate manifest schema is unsupported.'
Assert-Condition ([string]$candidate.version -cmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[A-Za-z-][0-9A-Za-z-]*))*)?$') 'Candidate version is not strict SemVer without build metadata.'
Assert-ExactProperties $candidate.source @('repository', 'commitSha', 'ref', 'workflowPath', 'workflowRef', 'workflowRunId', 'workflowRunAttempt', 'artifactId', 'artifactDigestSha256') @('repository', 'commitSha', 'ref', 'workflowPath', 'workflowRef', 'workflowRunId', 'workflowRunAttempt', 'artifactId', 'artifactDigestSha256') 'candidate source'
Assert-Condition ([string]$candidate.source.repository -ceq $fixed.Repository) 'Candidate repository is not the fixed repository.'
Assert-Condition ([string]$candidate.source.commitSha -cmatch '^[0-9a-f]{40}$') 'Candidate commit SHA is malformed.'
Assert-Condition ([string]$candidate.source.ref -ceq 'refs/heads/main') 'Candidate source ref is not protected main.'
Assert-Condition ([string]$candidate.source.workflowPath -ceq '.github/workflows/release-candidate.yml') 'Candidate workflow path is not fixed.'
$expectedWorkflowRef = "$($fixed.Repository)/.github/workflows/release-candidate.yml@refs/heads/main"
Assert-Condition ([string]$candidate.source.workflowRef -ceq $expectedWorkflowRef) 'Candidate workflow ref is not the fixed protected-main workflow ref.'
Assert-Condition ([int64]$candidate.source.workflowRunId -gt 0) 'Candidate workflow run ID is malformed.'
Assert-Condition ([int]$candidate.source.workflowRunAttempt -gt 0) 'Candidate workflow run attempt is malformed.'
Assert-Condition ($null -eq $candidate.source.artifactId -and $null -eq $candidate.source.artifactDigestSha256) 'Payload manifest must not claim post-upload artifact identity.'
Assert-ExactProperties $candidate.artifacts @('setupExe', 'appMsi', 'runtimeMsi', 'sbom', 'checksum') @('setupExe', 'appMsi', 'runtimeMsi', 'sbom', 'checksum') 'candidate artifacts'
Assert-ExactProperties $candidate.signing @('configured', 'outerPackageStatuses', 'disclosure') @('configured', 'outerPackageStatuses', 'disclosure') 'candidate signing'
Assert-Condition ($candidate.signing.configured -is [bool]) 'Candidate signing.configured must be Boolean.'
Assert-Condition (-not [string]::IsNullOrWhiteSpace([string]$candidate.signing.disclosure)) 'Candidate signing disclosure is empty.'
Assert-ExactProperties $candidate.signing.outerPackageStatuses @('setupExe', 'appMsi', 'runtimeMsi') @('setupExe', 'appMsi', 'runtimeMsi') 'outer package signing statuses'
Assert-ExactProperties $candidate.artifacts.setupExe @('fileName', 'sha256', 'sizeBytes', 'authenticodeStatus', 'bundleProviderKey', 'bundleUpgradeCode', 'burnEngine') @('fileName', 'sha256', 'sizeBytes', 'authenticodeStatus', 'bundleProviderKey', 'bundleUpgradeCode', 'burnEngine') 'setup artifact'
Assert-ExactProperties $candidate.artifacts.setupExe.burnEngine @('sizeBytes', 'sha256') @('sizeBytes', 'sha256') 'Burn engine fingerprint'
foreach ($msiProperty in @('appMsi', 'runtimeMsi')) {
    Assert-ExactProperties $candidate.artifacts.$msiProperty @('fileName', 'sha256', 'sizeBytes', 'authenticodeStatus', 'productCode', 'packageCode', 'upgradeCode', 'productVersion') @('fileName', 'sha256', 'sizeBytes', 'authenticodeStatus', 'productCode', 'packageCode', 'upgradeCode', 'productVersion') "candidate $msiProperty artifact"
}
foreach ($dataProperty in @('checksum', 'sbom')) {
    Assert-ExactProperties $candidate.artifacts.$dataProperty @('fileName', 'sha256', 'sizeBytes') @('fileName', 'sha256', 'sizeBytes') "candidate $dataProperty artifact"
}

Assert-ExactProperties $provenance @('schema', 'repository', 'sourceCommitSha', 'workflowRunId', 'workflowRunAttempt', 'artifactId', 'artifactName', 'artifactDigest', 'artifactArchiveSizeBytes', 'candidateManifestSha256') @('schema', 'repository', 'sourceCommitSha', 'workflowRunId', 'workflowRunAttempt', 'artifactId', 'artifactName', 'artifactDigest', 'artifactArchiveSizeBytes', 'candidateManifestSha256') 'provenance envelope'
Assert-Condition ([string]$provenance.schema -ceq 'distraction-firewall/live-validation-provenance/v1') 'Provenance envelope schema is unsupported.'
Assert-Condition ([string]$provenance.repository -ceq $fixed.Repository) 'Provenance repository is not fixed.'
Assert-Condition ([string]$provenance.sourceCommitSha -ceq [string]$candidate.source.commitSha) 'Provenance source SHA differs from the payload manifest.'
Assert-Condition ([int64]$provenance.workflowRunId -eq [int64]$candidate.source.workflowRunId) 'Provenance workflow run differs from the payload manifest.'
Assert-Condition ([int]$provenance.workflowRunAttempt -eq [int]$candidate.source.workflowRunAttempt) 'Provenance workflow run attempt differs from the payload manifest.'
Assert-Condition ([string]$provenance.artifactId -cmatch '^[1-9][0-9]*$') 'Provenance artifact ID is malformed.'
Assert-Condition ([string]$provenance.artifactName -cmatch '^release-candidate-[0-9A-Za-z.-]+-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*$') 'Provenance artifact name is malformed.'
Assert-Condition ([string]$provenance.artifactName -ceq ("release-candidate-{0}-{1}-{2}-{3}" -f $candidate.version, $candidate.source.commitSha, $candidate.source.workflowRunId, $candidate.source.workflowRunAttempt)) 'Provenance artifact name is not the exact candidate/run-derived name.'
Assert-Condition ([string]$provenance.artifactDigest -cmatch '^sha256:[0-9a-f]{64}$') 'Provenance artifact digest is malformed.'
Assert-Condition ([int64]$provenance.artifactArchiveSizeBytes -gt 0) 'Provenance artifact archive size is malformed.'
Assert-HexSha256 ([string]$provenance.candidateManifestSha256) 'provenance candidateManifestSha256'
Assert-Condition ([string]$provenance.candidateManifestSha256 -ceq $manifestSha256) 'Provenance does not pin the exact candidate manifest.'
Assert-Condition ($candidateArchiveItem.Length -eq [int64]$provenance.artifactArchiveSizeBytes) 'Raw artifact archive size differs from the provenance envelope.'
Assert-Condition (("sha256:{0}" -f (Get-LowerSha256 $candidateArchiveItem.FullName)) -ceq [string]$provenance.artifactDigest) 'Raw artifact archive SHA-256 differs from the GitHub artifact digest.'

$artifactApi = Get-GitHubApiJson "repos/$($fixed.Repository)/actions/artifacts/$($provenance.artifactId)"
Assert-Condition ([string]$artifactApi.id -ceq [string]$provenance.artifactId) 'GitHub artifact ID differs from the provenance envelope.'
Assert-Condition ([string]$artifactApi.name -ceq [string]$provenance.artifactName) 'GitHub artifact name differs from the provenance envelope.'
Assert-Condition (-not [bool]$artifactApi.expired) 'GitHub artifact is expired.'
Assert-Condition ([string]$artifactApi.digest -ceq [string]$provenance.artifactDigest) 'GitHub artifact API digest differs from the provenance envelope.'
Assert-Condition ([int64]$artifactApi.size_in_bytes -eq [int64]$provenance.artifactArchiveSizeBytes) 'GitHub artifact API size differs from the provenance envelope.'
Assert-Condition ([int64]$artifactApi.workflow_run.id -eq [int64]$provenance.workflowRunId) 'GitHub artifact belongs to a different workflow run.'
$runApi = Get-GitHubApiJson "repos/$($fixed.Repository)/actions/runs/$($provenance.workflowRunId)"
Assert-Condition ([string]$runApi.head_sha -ceq [string]$provenance.sourceCommitSha) 'GitHub workflow run source SHA differs from the provenance envelope.'
Assert-Condition ([string]$runApi.head_repository.full_name -ceq $fixed.Repository) 'GitHub workflow run source repository differs from the fixed repository.'
Assert-Condition ([int]$runApi.run_attempt -eq [int]$provenance.workflowRunAttempt) 'GitHub workflow run attempt differs from the provenance envelope.'
Assert-Condition ([string]$runApi.head_branch -ceq 'main' -and [string]$runApi.event -ceq 'workflow_dispatch') 'GitHub workflow run is not the reviewed main workflow_dispatch.'
Assert-Condition ([string]$runApi.path -ceq '.github/workflows/release-candidate.yml') 'GitHub workflow run path differs from the fixed candidate workflow.'
Assert-Condition ([string]$runApi.status -ceq 'completed' -and [string]$runApi.conclusion -ceq 'success') 'GitHub workflow run has not completed successfully.'

$setup = $candidate.artifacts.setupExe
$appMsi = $candidate.artifacts.appMsi
$runtimeMsi = $candidate.artifacts.runtimeMsi
Assert-Condition ([string]$candidate.signing.outerPackageStatuses.setupExe -ceq [string]$setup.authenticodeStatus) 'Setup signing summary differs from its artifact record.'
Assert-Condition ([string]$candidate.signing.outerPackageStatuses.appMsi -ceq [string]$appMsi.authenticodeStatus) 'App MSI signing summary differs from its artifact record.'
Assert-Condition ([string]$candidate.signing.outerPackageStatuses.runtimeMsi -ceq [string]$runtimeMsi.authenticodeStatus) 'Runtime MSI signing summary differs from its artifact record.'
if ([bool]$candidate.signing.configured) {
    Assert-Condition (@($candidate.signing.outerPackageStatuses.PSObject.Properties.Value | Where-Object { [string]$_ -cne 'Valid' }).Count -eq 0) 'Configured signing requires all outer packages to be Valid.'
}
else {
    Assert-Condition (@($candidate.signing.outerPackageStatuses.PSObject.Properties.Value | Where-Object { [string]$_ -cne 'NotSigned' }).Count -eq 0) 'Unsigned candidate records must consistently be NotSigned.'
}
$setupPath = Assert-Artifact $setup $packageRoot 'setup executable' -Binary
$appMsiPath = Assert-Artifact $appMsi $packageRoot 'App MSI' -Binary
$runtimeMsiPath = Assert-Artifact $runtimeMsi $packageRoot 'Runtime MSI' -Binary
$sbomPath = Assert-Artifact $candidate.artifacts.sbom $packageRoot 'SPDX inventory'
$checksumsPath = Assert-Artifact $candidate.artifacts.checksum $packageRoot 'checksum inventory'

Assert-CanonicalGuid ([string]$setup.bundleProviderKey) 'Bundle provider key'
Assert-Condition ([string]$setup.bundleUpgradeCode -ceq $fixed.BundleUpgradeCode) 'Bundle UpgradeCode is not fixed.'
Assert-Condition ([int64]$setup.burnEngine.sizeBytes -gt 0) 'Burn engine size must be positive.'
Assert-HexSha256 ([string]$setup.burnEngine.sha256) 'Burn engine sha256'

foreach ($pair in @(
    [pscustomobject]@{ Artifact = $appMsi; Path = $appMsiPath; Name = 'App'; Upgrade = $fixed.AppUpgradeCode },
    [pscustomobject]@{ Artifact = $runtimeMsi; Path = $runtimeMsiPath; Name = 'Runtime'; Upgrade = $fixed.RuntimeUpgradeCode }
)) {
    foreach ($guidProperty in @('productCode', 'packageCode', 'upgradeCode')) {
        Assert-CanonicalGuid ([string]$pair.Artifact.$guidProperty) "$($pair.Name) $guidProperty"
    }
    Assert-Condition ([string]$pair.Artifact.upgradeCode -ceq $pair.Upgrade) "$($pair.Name) UpgradeCode is not fixed."
    $observed = Get-MsiIdentity $pair.Path
    Assert-Condition ($observed.product_code -ceq [string]$pair.Artifact.productCode) "$($pair.Name) ProductCode differs from the MSI."
    Assert-Condition ($observed.package_code -ceq [string]$pair.Artifact.packageCode) "$($pair.Name) PackageCode differs from the MSI."
    Assert-Condition ($observed.upgrade_code -ceq [string]$pair.Artifact.upgradeCode) "$($pair.Name) UpgradeCode differs from the MSI."
    Assert-Condition ($observed.product_version -ceq [string]$pair.Artifact.productVersion) "$($pair.Name) ProductVersion differs from the MSI."
}

$expectedChecksumLines = @(
    foreach ($path in @($setupPath, $appMsiPath, $runtimeMsiPath, $sbomPath) | Sort-Object { [IO.Path]::GetFileName($_) }) {
        "$(Get-LowerSha256 $path)  $([IO.Path]::GetFileName($path))"
    }
)
$actualChecksumLines = @([IO.File]::ReadAllLines($checksumsPath))
Assert-Condition (-not [bool](Compare-Object -ReferenceObject $expectedChecksumLines -DifferenceObject $actualChecksumLines)) 'Checksum inventory is not the exact four-file inventory.'

$candidateBaseName = "distraction-firewall-$($candidate.version)"
$hostedEvidencePath = Join-Path $packageRoot "$candidateBaseName.hosted-evidence.json"
$subjectsPath = Join-Path $packageRoot "$candidateBaseName.candidate-subjects.sha256"
$attestationBundlePath = Join-Path $packageRoot "$candidateBaseName.provenance.bundle.json"
foreach ($path in @($hostedEvidencePath, $subjectsPath, $attestationBundlePath)) {
    Resolve-ExistingLeaf -Path $path -Description 'candidate provenance payload' | Out-Null
}
$expectedArchiveNames = @(
    [IO.Path]::GetFileName($setupPath),
    [IO.Path]::GetFileName($appMsiPath),
    [IO.Path]::GetFileName($runtimeMsiPath),
    [IO.Path]::GetFileName($checksumsPath),
    [IO.Path]::GetFileName($sbomPath),
    [IO.Path]::GetFileName($candidateManifestItem.FullName),
    [IO.Path]::GetFileName($hostedEvidencePath),
    [IO.Path]::GetFileName($subjectsPath),
    [IO.Path]::GetFileName($attestationBundlePath)
)
Assert-Condition (@($expectedArchiveNames | Sort-Object -Unique).Count -eq 9) 'Candidate archive filenames must be nine unique case-insensitive leaves.'
Assert-Condition ([IO.Path]::GetFileName($candidateManifestItem.FullName) -ceq "$candidateBaseName.candidate-manifest.json") 'Candidate manifest filename is not canonical.'
$expectedSubjectPaths = @($setupPath, $appMsiPath, $runtimeMsiPath, $checksumsPath, $sbomPath, $candidateManifestItem.FullName, $hostedEvidencePath)
$expectedSubjectLines = @(
    $expectedSubjectPaths | Sort-Object { [IO.Path]::GetFileName($_) } | ForEach-Object {
        "$(Get-LowerSha256 $_)  $([IO.Path]::GetFileName($_))"
    }
)
$actualSubjectLines = @([IO.File]::ReadAllLines($subjectsPath))
Assert-Condition (-not [bool](Compare-Object -ReferenceObject $expectedSubjectLines -DifferenceObject $actualSubjectLines)) 'Candidate subject checksum inventory is not the exact seven-file inventory.'
$hostedEvidence = Get-Content -LiteralPath $hostedEvidencePath -Raw | ConvertFrom-Json
Assert-ExactProperties $hostedEvidence @('schema', 'result', 'candidateManifestSha256', 'sourceCommitSha', 'workflowRunId', 'workflowRunAttempt', 'checks', 'limitations') @('schema', 'result', 'candidateManifestSha256', 'sourceCommitSha', 'workflowRunId', 'workflowRunAttempt', 'checks', 'limitations') 'hosted candidate evidence'
Assert-Condition ([string]$hostedEvidence.schema -ceq 'distraction-firewall/hosted-candidate-validation/v1' -and [string]$hostedEvidence.result -ceq 'passed') 'Hosted candidate evidence did not pass.'
Assert-Condition ([string]$hostedEvidence.candidateManifestSha256 -ceq $manifestSha256) 'Hosted evidence does not bind the exact candidate manifest.'
Assert-Condition ([string]$hostedEvidence.sourceCommitSha -ceq [string]$candidate.source.commitSha) 'Hosted evidence source SHA mismatch.'
Assert-Condition ([int64]$hostedEvidence.workflowRunId -eq [int64]$candidate.source.workflowRunId -and [int]$hostedEvidence.workflowRunAttempt -eq [int]$candidate.source.workflowRunAttempt) 'Hosted evidence workflow run mismatch.'

$archiveExpectedHashes = @{
    ([IO.Path]::GetFileName($candidateManifestItem.FullName)) = $manifestSha256
    ([IO.Path]::GetFileName($setupPath)) = [string]$setup.sha256
    ([IO.Path]::GetFileName($appMsiPath)) = [string]$appMsi.sha256
    ([IO.Path]::GetFileName($runtimeMsiPath)) = [string]$runtimeMsi.sha256
    ([IO.Path]::GetFileName($sbomPath)) = [string]$candidate.artifacts.sbom.sha256
    ([IO.Path]::GetFileName($checksumsPath)) = [string]$candidate.artifacts.checksum.sha256
    ([IO.Path]::GetFileName($hostedEvidencePath)) = (Get-LowerSha256 $hostedEvidencePath)
    ([IO.Path]::GetFileName($subjectsPath)) = (Get-LowerSha256 $subjectsPath)
    ([IO.Path]::GetFileName($attestationBundlePath)) = (Get-LowerSha256 $attestationBundlePath)
}
Assert-ArchiveMatchesExtraction -ArchivePath $candidateArchiveItem.FullName -ExtractedDirectory $packageRoot -ExpectedNames $expectedArchiveNames -ExpectedHashes $archiveExpectedHashes

foreach ($subjectPath in $expectedSubjectPaths) {
    $attestationCall = Invoke-TrustedGitHubCli $trustedGitHubCli @(
        'attestation', 'verify', $subjectPath,
        '--repo', [string]$fixed.Repository,
        '--bundle', $attestationBundlePath,
        '--signer-workflow', "$($fixed.Repository)/.github/workflows/release-candidate.yml",
        '--source-digest', [string]$candidate.source.commitSha,
        '--source-ref', 'refs/heads/main',
        '--deny-self-hosted-runners'
    ) -Token $trustedGitHubToken
    Assert-Condition ($attestationCall.exit_code -eq 0) "GitHub provenance verification failed for $([IO.Path]::GetFileName($subjectPath)): $(@($attestationCall.output) -join ' ')"
}

$resolvedRecovery = $null
if (-not [string]::IsNullOrWhiteSpace($RecoveryManifestPath)) {
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($RecoveryPackageDirectory)) 'RecoveryPackageDirectory is required with RecoveryManifestPath.'
    $recoveryManifestItem = Resolve-ExistingLeaf -Path $RecoveryManifestPath -Description 'Runtime recovery manifest'
    $recoveryRoot = (Resolve-ExistingDirectory -Path $RecoveryPackageDirectory -Description 'Runtime recovery package directory').FullName
    $recoveryManifestSha256 = Get-LowerSha256 $recoveryManifestItem.FullName
    $recovery = Get-Content -LiteralPath $recoveryManifestItem.FullName -Raw | ConvertFrom-Json
    Assert-ExactProperties $recovery @('schema', 'incidentId', 'approvedForMachineRecovery', 'mode', 'runtimeMsi', 'expectedInstalled', 'orphanBundleProviderKeys', 'orphanPackageCaches') @('schema', 'incidentId', 'approvedForMachineRecovery', 'mode', 'runtimeMsi', 'expectedInstalled', 'orphanBundleProviderKeys', 'orphanPackageCaches') 'Runtime recovery manifest'
    Assert-Condition ([string]$recovery.schema -ceq 'distraction-firewall/runtime-recovery/v1') 'Runtime recovery manifest schema is unsupported.'
    Assert-ApprovedRecoveryIncident $recovery $recoveryManifestSha256
    Assert-ExactProperties $recovery.runtimeMsi @('fileName', 'size', 'sha256', 'authenticodeStatus', 'productCode', 'packageCode', 'upgradeCode', 'productVersion') @('fileName', 'size', 'sha256', 'authenticodeStatus', 'productCode', 'packageCode', 'upgradeCode', 'productVersion') 'recovery Runtime MSI'
    Assert-ExactProperties $recovery.expectedInstalled @('productCode', 'packageCode', 'productVersion', 'localPackage') @('productCode', 'packageCode', 'productVersion', 'localPackage') 'expected installed Runtime'
    Assert-ExactProperties $recovery.expectedInstalled.localPackage @('sizeBytes', 'sha256') @('sizeBytes', 'sha256') 'expected installed LocalPackage'
    $recoveryPath = Assert-Artifact $recovery.runtimeMsi $recoveryRoot 'Runtime recovery MSI' -Binary
    Assert-CanonicalGuid ([string]$recovery.runtimeMsi.productCode) 'recovery Runtime ProductCode'
    Assert-CanonicalGuid ([string]$recovery.runtimeMsi.packageCode) 'recovery Runtime PackageCode'
    Assert-Condition ([string]$recovery.runtimeMsi.upgradeCode -ceq $fixed.RuntimeUpgradeCode) 'Recovery MSI is outside the fixed Runtime UpgradeCode family.'
    $observedRecovery = Get-MsiIdentity $recoveryPath
    Assert-Condition ($observedRecovery.product_code -ceq [string]$recovery.runtimeMsi.productCode) 'Recovery ProductCode differs from the MSI.'
    Assert-Condition ($observedRecovery.package_code -ceq [string]$recovery.runtimeMsi.packageCode) 'Recovery PackageCode differs from the MSI.'
    Assert-Condition ($observedRecovery.upgrade_code -ceq [string]$recovery.runtimeMsi.upgradeCode) 'Recovery UpgradeCode differs from the MSI.'
    Assert-Condition ($observedRecovery.product_version -ceq [string]$recovery.runtimeMsi.productVersion) 'Recovery ProductVersion differs from the MSI.'
    Assert-CanonicalGuid ([string]$recovery.expectedInstalled.productCode) 'expected installed ProductCode'
    Assert-CanonicalGuid ([string]$recovery.expectedInstalled.packageCode) 'expected installed PackageCode'
    Assert-Condition ([string]$recovery.expectedInstalled.productCode -ceq [string]$recovery.runtimeMsi.productCode) 'Recovery MSI must recache the exact installed ProductCode.'
    Assert-Condition ([string]$recovery.expectedInstalled.productVersion -ceq [string]$recovery.runtimeMsi.productVersion) 'Recovery MSI ProductVersion differs from the expected installed version.'
    Assert-Condition ([int64]$recovery.expectedInstalled.localPackage.sizeBytes -gt 0) 'Expected Windows Installer LocalPackage size is invalid.'
    Assert-HexSha256 ([string]$recovery.expectedInstalled.localPackage.sha256) 'expected Windows Installer LocalPackage SHA-256'
    foreach ($bundleKey in @($recovery.orphanBundleProviderKeys)) { Assert-CanonicalGuid ([string]$bundleKey) 'orphan Bundle provider key' }
    foreach ($cache in @($recovery.orphanPackageCaches)) {
        Assert-ExactProperties $cache @('directoryName', 'dependencyProviderKey', 'productCode', 'packageCode', 'upgradeCode', 'productVersion', 'payload') @('directoryName', 'dependencyProviderKey', 'productCode', 'packageCode', 'upgradeCode', 'productVersion', 'payload') 'orphan package cache'
        Assert-ExactProperties $cache.payload @('fileName', 'sizeBytes', 'sha256') @('fileName', 'sizeBytes', 'sha256') 'orphan package cache payload'
        Assert-CanonicalGuid ([string]$cache.productCode) 'orphan cache ProductCode'
        Assert-CanonicalGuid ([string]$cache.packageCode) 'orphan cache PackageCode'
        Assert-CanonicalGuid ([string]$cache.upgradeCode) 'orphan cache UpgradeCode'
        Assert-Condition ([string]$cache.upgradeCode -cin @($fixed.AppUpgradeCode, $fixed.RuntimeUpgradeCode)) 'Orphan cache is outside the fixed App/Runtime families.'
        Assert-Condition ([string]$cache.productVersion -cmatch '^[0-9]+\.[0-9]+\.[0-9]+$') 'Orphan cache ProductVersion is malformed.'
        $expectedDirectory = "{0}v{1}" -f $cache.productCode, $cache.productVersion
        $expectedProvider = "{0}_v{1}" -f $cache.productCode, $cache.productVersion
        Assert-Condition ([string]$cache.directoryName -ceq $expectedDirectory) 'Orphan cache directory name is not derived from its exact ProductCode/version.'
        Assert-Condition ([string]$cache.dependencyProviderKey -ceq $expectedProvider) 'Orphan dependency provider key is not derived from its exact ProductCode/version.'
        Assert-SafeLeafName ([string]$cache.payload.fileName) 'orphan cache payload filename'
        Assert-Condition ([int64]$cache.payload.sizeBytes -gt 0) 'Orphan cache payload size is invalid.'
        Assert-HexSha256 ([string]$cache.payload.sha256) 'orphan cache payload SHA-256'
    }
    $resolvedRecovery = [ordered]@{
        manifest_path = $recoveryManifestItem.FullName
        manifest_size = $recoveryManifestItem.Length
        manifest_sha256 = $recoveryManifestSha256
        approved_manifest_sha256 = [string]$approvedRecovery.ManifestSha256
        manifest = $recovery
        msi_path = $recoveryPath
    }
}
else {
    Assert-Condition ([string]::IsNullOrWhiteSpace($RecoveryPackageDirectory)) 'RecoveryPackageDirectory cannot be supplied without RecoveryManifestPath.'
}

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
Assert-Condition (-not (Test-Path -LiteralPath $outputPath)) "Campaign output already exists; campaigns are single-use: $outputPath"
$outputParent = Split-Path -Parent $outputPath
Assert-Condition (Test-Path -LiteralPath $outputParent -PathType Container) "Campaign output parent is missing: $outputParent"
Assert-Condition (((Get-Item -LiteralPath $outputParent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Campaign output parent must not be a reparse point.'

$campaignId = [Guid]::NewGuid().ToString('D')
[byte[]]$phaseNonceBytes = New-Object byte[] 32
$nonceGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $nonceGenerator.GetBytes($phaseNonceBytes) }
finally { $nonceGenerator.Dispose() }
$phaseNonce = [Convert]::ToBase64String($phaseNonceBytes)
$campaign = [ordered]@{
    schema = 'distraction-firewall/live-validation-campaign/v1'
    campaign_id = $campaignId
    phase_nonce = $phaseNonce
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    owner_sid = $ownerSid
    output_root = $outputPath
    source = [ordered]@{
        repository = [string]$candidate.source.repository
        commit_sha = [string]$candidate.source.commitSha
        workflow_run_id = [int64]$candidate.source.workflowRunId
        workflow_run_attempt = [int]$candidate.source.workflowRunAttempt
        artifact_id = [string]$provenance.artifactId
        artifact_digest = [string]$provenance.artifactDigest
    }
    tooling = [ordered]@{
        github_cli = $trustedGitHubCli
    }
    input_records = [ordered]@{
        candidate_manifest_path = $candidateManifestItem.FullName
        candidate_manifest_size = $candidateManifestItem.Length
        candidate_manifest_sha256 = $manifestSha256
        provenance_envelope_path = $provenanceItem.FullName
        provenance_envelope_size = $provenanceItem.Length
        provenance_envelope_sha256 = $provenanceSha256
        artifact_archive_path = $candidateArchiveItem.FullName
        artifact_archive_size = $candidateArchiveItem.Length
        artifact_archive_sha256 = (Get-LowerSha256 $candidateArchiveItem.FullName)
    }
    candidate = [ordered]@{
        version = [string]$candidate.version
        setup = [ordered]@{
            path = $setupPath
            file_name = [string]$setup.fileName
            size = [int64]$setup.sizeBytes
            sha256 = [string]$setup.sha256
            authenticode_status = [string]$setup.authenticodeStatus
            bundle_provider_key = [string]$setup.bundleProviderKey
            bundle_upgrade_code = [string]$setup.bundleUpgradeCode
            burn_engine_size = [int64]$setup.burnEngine.sizeBytes
            burn_engine_sha256 = [string]$setup.burnEngine.sha256
        }
        app_msi = [ordered]@{
            path = $appMsiPath
            file_name = [string]$appMsi.fileName
            size = [int64]$appMsi.sizeBytes
            sha256 = [string]$appMsi.sha256
            authenticode_status = [string]$appMsi.authenticodeStatus
            product_code = [string]$appMsi.productCode
            package_code = [string]$appMsi.packageCode
            upgrade_code = [string]$appMsi.upgradeCode
            product_version = [string]$appMsi.productVersion
        }
        runtime_msi = [ordered]@{
            path = $runtimeMsiPath
            file_name = [string]$runtimeMsi.fileName
            size = [int64]$runtimeMsi.sizeBytes
            sha256 = [string]$runtimeMsi.sha256
            authenticode_status = [string]$runtimeMsi.authenticodeStatus
            product_code = [string]$runtimeMsi.productCode
            package_code = [string]$runtimeMsi.packageCode
            upgrade_code = [string]$runtimeMsi.upgradeCode
            product_version = [string]$runtimeMsi.productVersion
        }
        sbom = [ordered]@{ path = $sbomPath; size = [int64]$candidate.artifacts.sbom.sizeBytes; sha256 = [string]$candidate.artifacts.sbom.sha256 }
        checksums = [ordered]@{ path = $checksumsPath; size = [int64]$candidate.artifacts.checksum.sizeBytes; sha256 = [string]$candidate.artifacts.checksum.sha256 }
        hosted_evidence = [ordered]@{ path = $hostedEvidencePath; size = (Get-Item -LiteralPath $hostedEvidencePath -Force).Length; sha256 = (Get-LowerSha256 $hostedEvidencePath) }
        subjects = [ordered]@{ path = $subjectsPath; size = (Get-Item -LiteralPath $subjectsPath -Force).Length; sha256 = (Get-LowerSha256 $subjectsPath) }
        attestation_bundle = [ordered]@{ path = $attestationBundlePath; size = (Get-Item -LiteralPath $attestationBundlePath -Force).Length; sha256 = (Get-LowerSha256 $attestationBundlePath) }
    }
    recovery = $resolvedRecovery
    fixed = $fixed
    paths = [ordered]@{
        app_root = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Distraction Firewall')
        runtime_root = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Distraction Firewall Lease Runtime')
        runtime_data_root = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'DistractionFirewall\Runtime\v1')
        active_marker = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'DistractionFirewall\Runtime\v1\active-lease.json')
        cli = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Distraction Firewall\cli\distraction-firewall-cli.exe')
        app = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Distraction Firewall\app\distraction-firewall.exe')
        service_exe = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Distraction Firewall Lease Runtime\activation-service\distraction-firewall-activation-service.exe')
        runtime_seed_key = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Motoki0705\DistractionFirewall\Runtime'
        owner_temp_root = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
        common_start_menu_root = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonStartMenu)) 'Programs\Distraction Firewall')
        package_cache_root = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'Package Cache')
    }
}

$templateRoot = Join-Path $PSScriptRoot 'templates'
$childTemplatePath = Join-Path $templateRoot 'Invoke-ElevatedPhase.ps1.template'
$parentTemplatePath = Join-Path $templateRoot 'Start-Campaign.ps1.template'
foreach ($template in @($childTemplatePath, $parentTemplatePath)) {
    Resolve-ExistingLeaf -Path $template -Description 'campaign template' | Out-Null
}

$null = New-Item -ItemType Directory -Path $outputPath
$statePath = Join-Path $outputPath 'state'
$evidencePath = Join-Path $outputPath 'evidence'
$null = New-Item -ItemType Directory -Path $statePath
$null = New-Item -ItemType Directory -Path $evidencePath
$encoding = [Text.UTF8Encoding]::new($false)
$scriptEncoding = [Text.UTF8Encoding]::new($false)
$campaignBase64 = Convert-ToEmbeddedRecord $campaign
$childPath = Join-Path $outputPath 'Invoke-ElevatedPhase.ps1'
$parentPath = Join-Path $outputPath 'Start-LiveValidationCampaign.ps1'
$nativeWindowsPowerShell = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::System),
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe')
Resolve-ExistingLeaf -Path $nativeWindowsPowerShell -Description 'native Windows PowerShell 5.1' | Out-Null
$parentInvocation = "& '$nativeWindowsPowerShell' -NoLogo -NoProfile -ExecutionPolicy Bypass -File '$parentPath'"

$childContent = [IO.File]::ReadAllText($childTemplatePath).Replace('__CAMPAIGN_BASE64__', $campaignBase64)
Assert-Condition (-not $childContent.Contains('__CAMPAIGN_BASE64__')) 'Elevated template substitution failed.'
[IO.File]::WriteAllText($childPath, $childContent, $scriptEncoding)
$childSha256 = Get-LowerSha256 $childPath

$parentContent = [IO.File]::ReadAllText($parentTemplatePath).
    Replace('__CAMPAIGN_BASE64__', $campaignBase64).
    Replace('__ELEVATED_RUNNER_SHA256__', $childSha256)
Assert-Condition (-not $parentContent.Contains('__CAMPAIGN_BASE64__') -and -not $parentContent.Contains('__ELEVATED_RUNNER_SHA256__')) 'Parent template substitution failed.'
[IO.File]::WriteAllText($parentPath, $parentContent, $scriptEncoding)
$parentSha256 = Get-LowerSha256 $parentPath

[IO.File]::WriteAllText((Join-Path $outputPath 'candidate-manifest.json'), [IO.File]::ReadAllText($candidateManifestItem.FullName), $encoding)
[IO.File]::WriteAllText((Join-Path $outputPath 'provenance-envelope.json'), [IO.File]::ReadAllText($provenanceItem.FullName), $encoding)
if ($null -ne $resolvedRecovery) {
    [IO.File]::WriteAllText((Join-Path $outputPath 'runtime-recovery-manifest.json'), [IO.File]::ReadAllText($resolvedRecovery.manifest_path), $encoding)
}

$lock = [ordered]@{
    schema = 'distraction-firewall/live-validation-lock/v1'
    campaign_id = $campaignId
    owner_sid = $ownerSid
    candidate_version = [string]$candidate.version
    source_commit_sha = [string]$candidate.source.commitSha
    workflow_run_id = [string]$candidate.source.workflowRunId
    artifact_id = [string]$provenance.artifactId
    artifact_digest = [string]$provenance.artifactDigest
    tooling = [ordered]@{
        github_cli = $trustedGitHubCli
    }
    generated_files = @(
        [ordered]@{ name = 'Start-LiveValidationCampaign.ps1'; sha256 = $parentSha256 },
        [ordered]@{ name = 'Invoke-ElevatedPhase.ps1'; sha256 = $childSha256 },
        [ordered]@{ name = 'candidate-manifest.json'; sha256 = (Get-LowerSha256 (Join-Path $outputPath 'candidate-manifest.json')) },
        [ordered]@{ name = 'provenance-envelope.json'; sha256 = (Get-LowerSha256 (Join-Path $outputPath 'provenance-envelope.json')) }
    )
    artifacts = @(
        [ordered]@{ role = 'artifact-archive'; path = $candidateArchiveItem.FullName; size = $candidateArchiveItem.Length; sha256 = (Get-LowerSha256 $candidateArchiveItem.FullName) },
        [ordered]@{ role = 'setup'; path = $setupPath; size = [int64]$setup.sizeBytes; sha256 = [string]$setup.sha256 },
        [ordered]@{ role = 'app-msi'; path = $appMsiPath; size = [int64]$appMsi.sizeBytes; sha256 = [string]$appMsi.sha256 },
        [ordered]@{ role = 'runtime-msi'; path = $runtimeMsiPath; size = [int64]$runtimeMsi.sizeBytes; sha256 = [string]$runtimeMsi.sha256 },
        [ordered]@{ role = 'sbom'; path = $sbomPath; size = [int64]$candidate.artifacts.sbom.sizeBytes; sha256 = [string]$candidate.artifacts.sbom.sha256 },
        [ordered]@{ role = 'checksums'; path = $checksumsPath; size = [int64]$candidate.artifacts.checksum.sizeBytes; sha256 = [string]$candidate.artifacts.checksum.sha256 },
        [ordered]@{ role = 'hosted-evidence'; path = $hostedEvidencePath; size = (Get-Item -LiteralPath $hostedEvidencePath -Force).Length; sha256 = (Get-LowerSha256 $hostedEvidencePath) },
        [ordered]@{ role = 'candidate-subjects'; path = $subjectsPath; size = (Get-Item -LiteralPath $subjectsPath -Force).Length; sha256 = (Get-LowerSha256 $subjectsPath) },
        [ordered]@{ role = 'provenance-bundle'; path = $attestationBundlePath; size = (Get-Item -LiteralPath $attestationBundlePath -Force).Length; sha256 = (Get-LowerSha256 $attestationBundlePath) }
    )
    invocation = $parentInvocation
    elevated_prompt_count = 1
    lease_start_permitted = $false
}
if ($null -ne $resolvedRecovery) {
    $lock.generated_files += [ordered]@{ name = 'runtime-recovery-manifest.json'; sha256 = (Get-LowerSha256 (Join-Path $outputPath 'runtime-recovery-manifest.json')) }
    $lock.artifacts += [ordered]@{ role = 'recovery-manifest'; path = $resolvedRecovery.manifest_path; size = [int64]$resolvedRecovery.manifest_size; sha256 = [string]$resolvedRecovery.approved_manifest_sha256 }
    $lock.artifacts += [ordered]@{ role = 'recovery-runtime-msi'; path = $resolvedRecovery.msi_path; size = [int64]$resolvedRecovery.manifest.runtimeMsi.size; sha256 = [string]$resolvedRecovery.manifest.runtimeMsi.sha256 }
}
$lockJson = $lock | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText((Join-Path $outputPath 'campaign.lock.json'), "$lockJson$([Environment]::NewLine)", $encoding)

foreach ($generatedFile in Get-ChildItem -LiteralPath $outputPath -File) {
    $generatedFile.IsReadOnly = $true
}

Write-Host "Prepared single-use campaign: $outputPath"
Write-Host "Owner SID: $ownerSid"
Write-Host "Candidate: $($candidate.version) @ $($candidate.source.commitSha)"
Write-Host "Start later from non-elevated Windows PowerShell 5.1:"
Write-Host "  $parentInvocation"
