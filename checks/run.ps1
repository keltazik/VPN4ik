param([switch]$NativeRouting,[switch]$SettingsFeatures)
$ErrorActionPreference = 'Stop'
$vpnProjectRoot = Split-Path $PSScriptRoot -Parent
$vpnEnvironmentNames = @('DOTNET_CLI_HOME', 'APPDATA', 'LOCALAPPDATA', 'MSBuildEnableWorkloadResolver', 'DOTNET_GENERATE_ASPNET_CERTIFICATE')
$vpnSavedEnvironment = @{}
foreach ($vpnName in $vpnEnvironmentNames) {
    $vpnSavedEnvironment[$vpnName] = [Environment]::GetEnvironmentVariable($vpnName, 'Process')
}
Push-Location $vpnProjectRoot
try {
    $env:DOTNET_CLI_HOME = Join-Path $vpnProjectRoot '.dotnet-home'
    $env:APPDATA = Join-Path $vpnProjectRoot '.checks-data\AppData'
    $env:LOCALAPPDATA = Join-Path $vpnProjectRoot '.checks-data\LocalAppData'
    $env:MSBuildEnableWorkloadResolver = 'false'
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
    dotnet restore checks\VPN4ik.Checks.csproj --configfile NuGet.Config --packages .nuget -p:NuGetAudit=false --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Checks restore failed.' }
    if ($NativeRouting) { dotnet run --project checks\VPN4ik.Checks.csproj --configuration Release --no-restore --verbosity quiet -- --native-routing }
    elseif($SettingsFeatures) { dotnet run --project checks\VPN4ik.Checks.csproj --configuration Release --no-restore --verbosity quiet -- --settings-features }
    else { dotnet run --project checks\VPN4ik.Checks.csproj --configuration Release --no-restore --verbosity quiet }
    if ($LASTEXITCODE -ne 0) { throw 'Offline checks failed.' }
}
finally {
    Pop-Location
    foreach ($vpnName in $vpnEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($vpnName, $vpnSavedEnvironment[$vpnName], 'Process')
    }
}
