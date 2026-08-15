[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$solutionPath = Join-Path $repositoryRoot 'DistractionFirewall.slnx'

if (-not (Test-Path -LiteralPath $solutionPath -PathType Leaf)) {
    throw "Solution file not found: $solutionPath"
}

$dotnetArguments = @(
    'build'
    $solutionPath
    '--configuration'
    $Configuration
    '--no-restore'
    '--nologo'
    '--warnaserror'
    '-p:ContinuousIntegrationBuild=true'
)

Push-Location -LiteralPath $repositoryRoot
try {
    & dotnet @dotnetArguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet build failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
