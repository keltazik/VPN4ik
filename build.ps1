param([string]$OutputDirectory = 'artifacts\VPN4ik-routing')

$ErrorActionPreference = 'Stop'
$vpnProjectRoot = $PSScriptRoot
$vpnNames = @('DOTNET_CLI_HOME', 'APPDATA', 'MSBuildEnableWorkloadResolver', 'DOTNET_CLI_TELEMETRY_OPTOUT')
$vpnSaved = @{}
foreach ($vpnName in $vpnNames) { $vpnSaved[$vpnName] = [Environment]::GetEnvironmentVariable($vpnName, 'Process') }
Push-Location $vpnProjectRoot
try {
    if (!(Test-Path -LiteralPath 'source\VPNyan\VPNyan\Engine\xray.exe')) { & (Join-Path $vpnProjectRoot 'scripts\bootstrap-engine.ps1') }
    $env:DOTNET_CLI_HOME = Join-Path $vpnProjectRoot '.dotnet-home'
    $env:APPDATA = Join-Path $vpnProjectRoot '.dotnet-home\AppData'
    $env:MSBuildEnableWorkloadResolver = 'false'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    dotnet restore source\VPNyan\VPNyan\VPNyan.csproj -r win-x64 --configfile NuGet.Config --packages .nuget -p:SelfContained=true -p:NuGetAudit=false --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed.' }
    dotnet publish source\VPNyan\VPNyan\VPNyan.csproj -c Release -r win-x64 --self-contained true --no-restore -o $OutputDirectory --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
    Write-Output "Ready: $OutputDirectory\VPNyan.exe (copy the entire output folder)."
}
finally {
    Pop-Location
    foreach ($vpnName in $vpnNames) { [Environment]::SetEnvironmentVariable($vpnName, $vpnSaved[$vpnName], 'Process') }
}


