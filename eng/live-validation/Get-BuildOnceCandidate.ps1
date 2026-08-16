#requires -Version 5.1

<#+
.SYNOPSIS
Downloads a GitHub Actions build-once candidate without corrupting ZIP bytes.

.DESCRIPTION
Windows PowerShell 5.1 text redirection must not be used for artifact ZIPs.
This command uses HttpClient byte streams, verifies the GitHub API digest and
size before extraction, permits only a flat archive, and emits the external
provenance envelope consumed by New-LiveValidationCampaign.ps1.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[1-9][0-9]*$')]
    [string]$ArtifactId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$nativeSystemDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::System)).TrimEnd('\')
$nativeWindowsDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)).TrimEnd('\')
$trustedPowerShellHome = [IO.Path]::GetFullPath([IO.Path]::Combine($nativeSystemDirectory, 'WindowsPowerShell', 'v1.0')).TrimEnd('\')
if (-not ([IO.Path]::GetFullPath($PSHOME).TrimEnd('\').Equals($trustedPowerShellHome, [StringComparison]::OrdinalIgnoreCase))) {
    throw 'Candidate download must run in native Windows PowerShell 5.1.'
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
$repository = 'Motoki0705/distraction-firewall'

function Assert-Condition {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Import-TrustedSystemNetHttpAssembly {
    $systemNetHttpAssemblyIdentity = 'System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
    $trustedSystemNetHttpPath = [IO.Path]::Combine(
        $nativeWindowsDirectory,
        'Microsoft.Net',
        'assembly',
        'GAC_MSIL',
        'System.Net.Http',
        'v4.0_4.0.0.0__b03f5f7f11d50a3a',
        'System.Net.Http.dll')

    Assert-Condition ([IO.File]::Exists($trustedSystemNetHttpPath)) 'Trusted System.Net.Http assembly is missing from the native Windows GAC.'
    Assert-Condition (([IO.File]::GetAttributes($trustedSystemNetHttpPath) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Trusted System.Net.Http assembly is a reparse point.'
    try {
        $systemNetHttpAssembly = [Reflection.Assembly]::Load($systemNetHttpAssemblyIdentity)
    }
    catch {
        throw "Trusted System.Net.Http assembly could not be loaded: $($_.Exception.Message)"
    }

    Assert-Condition ($systemNetHttpAssembly.FullName -ceq $systemNetHttpAssemblyIdentity) 'Loaded System.Net.Http assembly identity is not the fixed Microsoft strong name.'
    Assert-Condition $systemNetHttpAssembly.GlobalAssemblyCache 'Loaded System.Net.Http assembly did not come from the native Windows GAC.'
    $loadedSystemNetHttpPath = [IO.Path]::GetFullPath($systemNetHttpAssembly.Location)
    Assert-Condition ($loadedSystemNetHttpPath.Equals($trustedSystemNetHttpPath, [StringComparison]::OrdinalIgnoreCase)) 'Loaded System.Net.Http assembly path is not the fixed native Windows GAC path.'
}

$null = Import-TrustedSystemNetHttpAssembly

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
    # Exact write/delete/ACL bits plus generic write/all; composite FullControl
    # includes read/synchronize bits and must not be used as a bit mask.
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

function Invoke-GitHubJson {
    param(
        [Parameter(Mandatory)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)][string]$Uri
    )
    $response = $Client.GetAsync($Uri).GetAwaiter().GetResult()
    try {
        Assert-Condition $response.IsSuccessStatusCode "GitHub API request failed with HTTP $([int]$response.StatusCode)."
        return $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
    }
    finally { $response.Dispose() }
}

function Copy-ResponseBodyToNewFile {
    param(
        [Parameter(Mandatory)][Net.Http.HttpResponseMessage]$Response,
        [Parameter(Mandatory)][string]$Path
    )

    $source = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    try {
        $destination = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $source.CopyTo($destination) }
        finally { $destination.Dispose() }
    }
    finally { $source.Dispose() }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-Condition (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Candidate download/preparation must run non-elevated.'
Assert-Condition ([Environment]::Is64BitOperatingSystem -and [Environment]::Is64BitProcess) 'Candidate download requires native x64 PowerShell on x64 Windows.'
$trustedGitHubCli = Resolve-TrustedGitHubCli
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
Assert-Condition (-not (Test-Path -LiteralPath $outputRoot)) 'OutputDirectory already exists; downloads are immutable and never overwritten.'
$outputParent = Split-Path -Parent $outputRoot
Assert-Condition (Test-Path -LiteralPath $outputParent -PathType Container) 'OutputDirectory parent is missing.'
Assert-Condition (((Get-Item -LiteralPath $outputParent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputDirectory parent must not be a reparse point.'
$null = New-Item -ItemType Directory -Path $outputRoot
$candidateRoot = Join-Path $outputRoot 'candidate'
$null = New-Item -ItemType Directory -Path $candidateRoot
$archivePath = Join-Path $outputRoot "github-artifact-$ArtifactId.zip"

$token = Get-GitHubToken $trustedGitHubCli
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [Net.Http.HttpClient]::new($handler)
try {
    $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('distraction-firewall-live-validation/1')
    $client.DefaultRequestHeaders.Accept.ParseAdd('application/vnd.github+json')
    $client.DefaultRequestHeaders.Add('X-GitHub-Api-Version', '2022-11-28')
    $artifactApi = Invoke-GitHubJson $client "https://api.github.com/repos/$repository/actions/artifacts/$ArtifactId"
    Assert-Condition ([string]$artifactApi.id -ceq $ArtifactId) 'GitHub returned a different artifact ID.'
    Assert-Condition (-not [bool]$artifactApi.expired) 'The candidate artifact is expired.'
    Assert-Condition ([string]$artifactApi.digest -cmatch '^sha256:[0-9a-f]{64}$') 'GitHub artifact digest is unavailable or malformed.'
    Assert-Condition ([int64]$artifactApi.size_in_bytes -gt 0) 'GitHub artifact size is invalid.'
    Assert-Condition ([int64]$artifactApi.workflow_run.id -gt 0) 'GitHub artifact has no workflow-run binding.'
    $runApi = Invoke-GitHubJson $client "https://api.github.com/repos/$repository/actions/runs/$($artifactApi.workflow_run.id)"
    Assert-Condition ([string]$runApi.status -ceq 'completed' -and [string]$runApi.conclusion -ceq 'success') 'Candidate workflow run has not completed successfully.'
    Assert-Condition ([string]$runApi.head_repository.full_name -ceq $repository) 'Candidate workflow run source repository is not fixed.'
    Assert-Condition ([string]$runApi.head_branch -ceq 'main' -and [string]$runApi.event -ceq 'workflow_dispatch') 'Candidate workflow run is not a protected-main workflow_dispatch.'
    Assert-Condition ([string]$runApi.path -ceq '.github/workflows/release-candidate.yml') 'Candidate came from a different workflow.'
    Assert-Condition ([string]$runApi.head_sha -cmatch '^[0-9a-f]{40}$' -and [int]$runApi.run_attempt -gt 0) 'Candidate run identity is malformed.'

    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, [string]$artifactApi.archive_download_url)
    $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    try {
        if ($response.IsSuccessStatusCode) {
            Copy-ResponseBodyToNewFile -Response $response -Path $archivePath
        }
        else {
            $redirectCodes = @(301, 302, 303, 307, 308)
            Assert-Condition ([int]$response.StatusCode -in $redirectCodes) "Artifact download failed with HTTP $([int]$response.StatusCode)."
            $redirectUri = $response.Headers.Location
            Assert-Condition ($null -ne $redirectUri) 'GitHub artifact download redirect has no Location header.'
            if (-not $redirectUri.IsAbsoluteUri) {
                $redirectUri = [Uri]::new($request.RequestUri, $redirectUri)
            }
            Assert-Condition ($redirectUri.Scheme -ceq 'https' -and [string]::IsNullOrEmpty($redirectUri.UserInfo)) 'GitHub artifact redirect must be an HTTPS URL without user information.'

            # Never forward the GitHub token to the signed blob URL. A separate
            # anonymous client follows any storage-host redirect chain.
            $downloadHandler = [Net.Http.HttpClientHandler]::new()
            $downloadHandler.AllowAutoRedirect = $true
            $downloadClient = [Net.Http.HttpClient]::new($downloadHandler)
            try {
                $downloadClient.DefaultRequestHeaders.UserAgent.ParseAdd('distraction-firewall-live-validation/1')
                $downloadResponse = $downloadClient.GetAsync($redirectUri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                try {
                    Assert-Condition $downloadResponse.IsSuccessStatusCode "Artifact blob download failed with HTTP $([int]$downloadResponse.StatusCode)."
                    Copy-ResponseBodyToNewFile -Response $downloadResponse -Path $archivePath
                }
                finally { $downloadResponse.Dispose() }
            }
            finally {
                $downloadClient.Dispose()
                $downloadHandler.Dispose()
            }
        }
    }
    finally {
        $response.Dispose()
        $request.Dispose()
    }
}
finally {
    $client.Dispose()
    $handler.Dispose()
    $token = $null
}

$archiveItem = Get-Item -LiteralPath $archivePath -Force
Assert-Condition ($archiveItem.Length -eq [int64]$artifactApi.size_in_bytes) 'Downloaded archive size differs from the GitHub API.'
$archiveHash = Get-LowerSha256 $archivePath
Assert-Condition (("sha256:$archiveHash") -ceq [string]$artifactApi.digest) 'Downloaded archive bytes differ from the GitHub API digest.'

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $archive.Entries) {
        Assert-Condition (-not [string]::IsNullOrEmpty($entry.Name)) 'Artifact archive contains a directory entry.'
        Assert-Condition ([IO.Path]::GetFileName($entry.FullName) -ceq $entry.FullName) "Artifact archive is not flat: $($entry.FullName)"
        Assert-Condition ($entry.FullName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -lt 0) "Artifact entry filename is invalid: $($entry.FullName)"
        Assert-Condition $seen.Add($entry.FullName) "Artifact archive contains a duplicate entry: $($entry.FullName)"
        $destination = Join-Path $candidateRoot $entry.FullName
        $input = $entry.Open()
        try {
            $output = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $input.CopyTo($output) }
            finally { $output.Dispose() }
        }
        finally { $input.Dispose() }
    }
}
finally { $archive.Dispose() }

$manifestFiles = @(Get-ChildItem -LiteralPath $candidateRoot -File -Filter '*.candidate-manifest.json')
Assert-Condition ($manifestFiles.Count -eq 1) 'Artifact must contain exactly one candidate manifest.'
$manifest = Get-Content -LiteralPath $manifestFiles[0].FullName -Raw | ConvertFrom-Json
Assert-Condition ([string]$manifest.schema -ceq 'distraction-firewall/build-once-candidate/v1') 'Candidate manifest schema is unsupported.'
Assert-Condition ([string]$manifest.source.repository -ceq $repository) 'Candidate manifest repository mismatch.'
Assert-Condition ([string]$manifest.source.commitSha -ceq [string]$runApi.head_sha) 'Candidate manifest source SHA differs from GitHub.'
Assert-Condition ([int64]$manifest.source.workflowRunId -eq [int64]$runApi.id -and [int]$manifest.source.workflowRunAttempt -eq [int]$runApi.run_attempt) 'Candidate manifest workflow-run identity differs from GitHub.'
Assert-Condition ([string]$manifest.source.workflowRef -ceq "$repository/.github/workflows/release-candidate.yml@refs/heads/main") 'Candidate workflow ref is not fixed.'

$envelope = [ordered]@{
    schema = 'distraction-firewall/live-validation-provenance/v1'
    repository = $repository
    sourceCommitSha = [string]$runApi.head_sha
    workflowRunId = [int64]$runApi.id
    workflowRunAttempt = [int]$runApi.run_attempt
    artifactId = $ArtifactId
    artifactName = [string]$artifactApi.name
    artifactDigest = [string]$artifactApi.digest
    artifactArchiveSizeBytes = [int64]$artifactApi.size_in_bytes
    candidateManifestSha256 = Get-LowerSha256 $manifestFiles[0].FullName
}
$receipt = [ordered]@{
    schema = 'distraction-firewall/github-artifact-api-receipt/v1'
    recordedAtUtc = [DateTime]::UtcNow.ToString('o')
    repository = $repository
    artifact = [ordered]@{
        id = $ArtifactId
        name = [string]$artifactApi.name
        sizeBytes = [int64]$artifactApi.size_in_bytes
        digest = [string]$artifactApi.digest
        expired = [bool]$artifactApi.expired
    }
    workflowRun = [ordered]@{
        id = [int64]$runApi.id
        attempt = [int]$runApi.run_attempt
        sourceCommitSha = [string]$runApi.head_sha
        sourceRepository = [string]$runApi.head_repository.full_name
        path = [string]$runApi.path
        event = [string]$runApi.event
        conclusion = [string]$runApi.conclusion
    }
    githubCli = $trustedGitHubCli
}
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $outputRoot 'provenance-envelope.json'), (($envelope | ConvertTo-Json -Depth 10) + [Environment]::NewLine), $utf8)
[IO.File]::WriteAllText((Join-Path $outputRoot 'github-api-receipt.json'), (($receipt | ConvertTo-Json -Depth 10) + [Environment]::NewLine), $utf8)
Write-Host "Downloaded and verified raw artifact: $archivePath"
Write-Host "Extracted candidate: $candidateRoot"
Write-Host "Provenance envelope: $(Join-Path $outputRoot 'provenance-envelope.json')"
