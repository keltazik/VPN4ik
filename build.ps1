param([string]$OutputDirectory = 'artifacts\VPN4ik-routing')

$ErrorActionPreference = 'Stop'
$vpnProjectRoot = $PSScriptRoot
$vpnNames = @('DOTNET_CLI_HOME', 'APPDATA', 'MSBuildEnableWorkloadResolver', 'DOTNET_CLI_TELEMETRY_OPTOUT')
$vpnSaved = @{}
foreach ($vpnName in $vpnNames) { $vpnSaved[$vpnName] = [Environment]::GetEnvironmentVariable($vpnName, 'Process') }
Push-Location $vpnProjectRoot
try {
    if (!(Test-Path -LiteralPath 'source\VPNyan\VPNyan\Engine\xray.exe')) { & (Join-Path $vpnProjectRoot 'scripts\bootstrap-engine.ps1') }
    & (Join-Path $vpnProjectRoot 'scripts\bootstrap-hiddify.ps1')
    $env:DOTNET_CLI_HOME = Join-Path $vpnProjectRoot '.dotnet-home'
    $env:APPDATA = Join-Path $vpnProjectRoot '.dotnet-home\AppData'
    $env:MSBuildEnableWorkloadResolver = 'false'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    dotnet restore source\VPNyan\VPNyan\VPNyan.csproj -r win-x64 --configfile NuGet.Config --packages .nuget -p:PublishProfile=Portable -p:NuGetAudit=false --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed.' }
    # Publish into a fresh directory so files from an earlier publish cannot leak into the release.
    $vpnPublish = Join-Path $vpnProjectRoot ('artifacts\publish-' + [Guid]::NewGuid().ToString('N'))
    dotnet publish source\VPNyan\VPNyan\VPNyan.csproj -c Release -p:PublishProfile=Portable --no-restore -o $vpnPublish --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
    & (Join-Path $vpnProjectRoot 'checks\check-portable.ps1') -BuildDirectory $vpnPublish
    $vpnDestination = [IO.Path]::GetFullPath((Join-Path $vpnProjectRoot $OutputDirectory))
    $vpnArtifacts = [IO.Path]::GetFullPath((Join-Path $vpnProjectRoot 'artifacts')) + [IO.Path]::DirectorySeparatorChar
    if (!$vpnDestination.StartsWith($vpnArtifacts, [StringComparison]::OrdinalIgnoreCase)) { throw 'OutputDirectory must be a subdirectory of artifacts.' }
    if (Test-Path -LiteralPath $vpnDestination) { Remove-Item -LiteralPath $vpnDestination -Recurse -Force }
    Move-Item -LiteralPath $vpnPublish -Destination $vpnDestination
    Write-Output "Ready: $OutputDirectory\VPNyan.exe (copy the entire output folder)."
}
finally {
    Pop-Location
    foreach ($vpnName in $vpnNames) { [Environment]::SetEnvironmentVariable($vpnName, $vpnSaved[$vpnName], 'Process') }
}


