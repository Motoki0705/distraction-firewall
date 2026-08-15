[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$ResultsDirectory = 'artifacts/test-results'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$testsRoot = Join-Path $repositoryRoot 'tests'

if (-not (Test-Path -LiteralPath $testsRoot -PathType Container)) {
    throw "Tests directory not found: $testsRoot"
}

if (-not [System.IO.Path]::IsPathRooted($ResultsDirectory)) {
    $ResultsDirectory = Join-Path $repositoryRoot $ResultsDirectory
}

$null = New-Item -ItemType Directory -Path $ResultsDirectory -Force

$testProjects = @(
    Get-ChildItem -LiteralPath $testsRoot -Recurse -File -Filter '*.csproj' |
        Sort-Object -Property FullName
)

if ($testProjects.Count -eq 0) {
    throw "No test projects were found below $testsRoot."
}

$failedProjects = [System.Collections.Generic.List[string]]::new()

Push-Location -LiteralPath $repositoryRoot
try {
    foreach ($testProject in $testProjects) {
        $logFileName = '{0}.trx' -f $testProject.BaseName
        $dotnetArguments = @(
            'test'
            $testProject.FullName
            '--configuration'
            $Configuration
            '--no-build'
            '--no-restore'
            '--nologo'
            '--results-directory'
            $ResultsDirectory
            '--logger'
            "trx;LogFileName=$logFileName"
        )

        & dotnet @dotnetArguments
        if ($LASTEXITCODE -ne 0) {
            $failedProjects.Add($testProject.FullName)
        }
    }
}
finally {
    Pop-Location
}

if ($failedProjects.Count -gt 0) {
    $projectList = $failedProjects -join [Environment]::NewLine
    throw "One or more test projects failed:$([Environment]::NewLine)$projectList"
}
