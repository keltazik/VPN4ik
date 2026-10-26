param([string]$BuildDirectory = 'artifacts\VPN4ik-routing')

$ErrorActionPreference = 'Stop'
$vpnRoot = Split-Path $PSScriptRoot -Parent
$vpnBuild = if ([IO.Path]::IsPathRooted($BuildDirectory)) {
    [IO.Path]::GetFullPath($BuildDirectory)
} else {
    [IO.Path]::GetFullPath((Join-Path $vpnRoot $BuildDirectory))
}
$vpnRequired = @(
    'VPNyan.exe', 'VPNyan.dll', 'VPNyan.deps.json', 'VPNyan.runtimeconfig.json',
    'hostfxr.dll', 'hostpolicy.dll', 'coreclr.dll', 'System.Private.CoreLib.dll',
    'PresentationFramework.dll', 'PresentationCore.dll', 'WindowsBase.dll'
)
foreach ($vpnFile in $vpnRequired) {
    $vpnPath = Join-Path $vpnBuild $vpnFile
    if (!(Test-Path -LiteralPath $vpnPath -PathType Leaf) -or (Get-Item -LiteralPath $vpnPath).Length -eq 0) {
        throw "Incomplete self-contained build: missing $vpnFile. Rebuild with build.ps1."
    }
}
$vpnOptions = (Get-Content -LiteralPath (Join-Path $vpnBuild 'VPNyan.runtimeconfig.json') -Raw | ConvertFrom-Json).runtimeOptions
if (!$vpnOptions -or $vpnOptions.framework -or $vpnOptions.frameworks) {
    throw 'This build requires an installed .NET runtime. Rebuild with build.ps1.'
}
$vpnFrameworks = @($vpnOptions.includedFrameworks | ForEach-Object { $_.name })
foreach ($vpnFramework in @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App')) {
    if ($vpnFrameworks -notcontains $vpnFramework) {
        throw "Self-contained runtime manifest is missing $vpnFramework. Rebuild with build.ps1."
    }
}
Write-Output 'Verified: .NET and Windows Desktop runtime are included in the application folder.'
