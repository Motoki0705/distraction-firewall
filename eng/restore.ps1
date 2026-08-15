[CmdletBinding()]
param(
    [switch]$UpdateLockFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$solutionPath = Join-Path $repositoryRoot 'DistractionFirewall.slnx'

if (-not (Test-Path -LiteralPath $solutionPath -PathType Leaf)) {
    throw "Solution file not found: $solutionPath"
}

$dotnetArguments = @(
    'restore'
    $solutionPath
    '--nologo'
)

if (-not $UpdateLockFiles) {
    $dotnetArguments += '--locked-mode'
}

Push-Location -LiteralPath $repositoryRoot
try {
    & dotnet @dotnetArguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet restore failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
