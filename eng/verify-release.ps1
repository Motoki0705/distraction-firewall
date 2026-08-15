[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Version,

    [string]$PackageDirectory = 'artifacts/package',

    [switch]$RequireSigning,

    [switch]$RequireDeferredActiveUninstall,

    [switch]$GenerateMetadata
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if (-not [System.IO.Path]::IsPathRooted($PackageDirectory)) {
    $PackageDirectory = Join-Path $repositoryRoot $PackageDirectory
}
$PackageDirectory = [System.IO.Path]::GetFullPath($PackageDirectory)

$verifyArguments = @{
    Version = $Version
    PackageDirectory = $PackageDirectory
}
if ($RequireSigning) {
    $verifyArguments.RequireSigning = $true
}
if ($RequireDeferredActiveUninstall) {
    $verifyArguments.RequireDeferredActiveUninstall = $true
}
& (Join-Path $PSScriptRoot 'verify-installer.ps1') @verifyArguments

$binaryArtifacts = @(
    [pscustomobject]@{
        Id = 'SPDXRef-Package-AppMsi'
        Path = Join-Path $PackageDirectory "distraction-firewall-app-$Version-win-x64.msi"
    },
    [pscustomobject]@{
        Id = 'SPDXRef-Package-RuntimeMsi'
        Path = Join-Path $PackageDirectory "distraction-firewall-runtime-$Version-win-x64.msi"
    },
    [pscustomobject]@{
        Id = 'SPDXRef-Package-SetupExe'
        Path = Join-Path $PackageDirectory "distraction-firewall-setup-$Version-win-x64.exe"
    }
)

$artifactInventory = @(
    foreach ($artifact in $binaryArtifacts) {
        $file = Get-Item -LiteralPath $artifact.Path
        [pscustomobject]@{
            Id = $artifact.Id
            Name = $file.Name
            Path = $file.FullName
            Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
)

$sbomPath = Join-Path $PackageDirectory "distraction-firewall-$Version.spdx.json"
$checksumsPath = Join-Path $PackageDirectory "distraction-firewall-$Version.sha256"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

if ($GenerateMetadata) {
    $namespaceSeed = ($artifactInventory | Sort-Object -Property Name | ForEach-Object { "$($_.Name):$($_.Sha256)" }) -join ';'
    $namespaceHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $namespaceBytes = [System.Text.Encoding]::UTF8.GetBytes("$Version;$namespaceSeed")
        $namespaceHash = ([BitConverter]::ToString($namespaceHasher.ComputeHash($namespaceBytes)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $namespaceHasher.Dispose()
    }

    $spdxPackages = @(
        foreach ($artifact in $artifactInventory) {
            [ordered]@{
                SPDXID = $artifact.Id
                name = $artifact.Name
                versionInfo = $Version
                supplier = 'NOASSERTION'
                downloadLocation = "https://github.com/Motoki0705/distraction-firewall/releases/download/v$Version/$($artifact.Name)"
                filesAnalyzed = $false
                checksums = @(
                    [ordered]@{
                        algorithm = 'SHA256'
                        checksumValue = $artifact.Sha256
                    }
                )
                licenseConcluded = 'NOASSERTION'
                licenseDeclared = 'NOASSERTION'
                copyrightText = 'NOASSERTION'
                comment = 'P1.5 distribution-artifact inventory only; source and dependency enumeration is not yet implemented.'
            }
        }
    )

    $spdxDocument = [ordered]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = "distraction-firewall-$Version-distribution-sbom-skeleton"
        documentNamespace = "https://github.com/Motoki0705/distraction-firewall/spdx/$Version/$namespaceHash"
        creationInfo = [ordered]@{
            created = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            creators = @('Tool: eng/verify-release.ps1')
            comment = 'Skeleton only: this inventories release binaries and does not claim complete source or dependency coverage.'
        }
        documentDescribes = @($artifactInventory.Id)
        packages = $spdxPackages
    }

    $spdxJson = $spdxDocument | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($sbomPath, "$spdxJson$([Environment]::NewLine)", $utf8NoBom)

    $checksumInputs = @($artifactInventory.Path) + @($sbomPath)
    $checksumLines = @(
        $checksumInputs |
            Sort-Object { [System.IO.Path]::GetFileName($_) } |
            ForEach-Object {
                $hash = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
                "$hash  $([System.IO.Path]::GetFileName($_))"
            }
    )
    [System.IO.File]::WriteAllLines($checksumsPath, $checksumLines, $utf8NoBom)
}

foreach ($metadataPath in @($sbomPath, $checksumsPath)) {
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw "Release metadata is missing: $metadataPath"
    }
}

$spdx = Get-Content -LiteralPath $sbomPath -Raw | ConvertFrom-Json
if ($spdx.spdxVersion -ne 'SPDX-2.3' -or $spdx.packages.Count -ne 3) {
    throw "The SPDX distribution inventory is malformed: $sbomPath"
}
if ($spdx.creationInfo.comment -notmatch 'Skeleton only') {
    throw 'The SPDX skeleton must explicitly disclaim complete dependency coverage.'
}

$checksumInputs = @($artifactInventory.Path) + @($sbomPath)
$expectedChecksumLines = @(
    $checksumInputs |
        Sort-Object { [System.IO.Path]::GetFileName($_) } |
        ForEach-Object {
            $hash = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $([System.IO.Path]::GetFileName($_))"
        }
)
$actualChecksumLines = @([System.IO.File]::ReadAllLines($checksumsPath))
if (Compare-Object -ReferenceObject $expectedChecksumLines -DifferenceObject $actualChecksumLines) {
    throw "Release checksums do not match the package payload: $checksumsPath"
}

Write-Host "Verified release payload for $Version."
