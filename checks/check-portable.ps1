param([Parameter(Mandatory = $true)][string]$BuildDirectory)
$ErrorActionPreference = 'Stop'
$vpnRoot = Split-Path $PSScriptRoot -Parent
$vpnBuild = (Resolve-Path -LiteralPath $BuildDirectory).Path
$vpnExecutable = Join-Path $vpnBuild 'VPNyan.exe'
if (!(Test-Path -LiteralPath $vpnExecutable)) { throw 'Build VPN4ik first.' }
# A loose runtimeconfig / managed DLL means this is not the portable single-file publish.
if ((Test-Path -LiteralPath (Join-Path $vpnBuild 'VPNyan.runtimeconfig.json')) -or
    (Test-Path -LiteralPath (Join-Path $vpnBuild 'VPNyan.dll'))) {
    throw 'Not a portable single-file build. Run build.ps1; do not package bin output.'
}
$vpnScratch = Join-Path $vpnRoot ('.checks-data\portable-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $vpnScratch | Out-Null
# Copy only the EXE and engine: no nearby .NET DLLs can mask missing bundled files.
Copy-Item -LiteralPath $vpnExecutable -Destination $vpnScratch
Copy-Item -LiteralPath (Join-Path $vpnBuild 'Engine') -Destination $vpnScratch -Recurse
$vpnResult = Join-Path $vpnScratch 'startup.json'
$vpnExtract = Join-Path $vpnScratch 'bundle'
$vpnStart = New-Object System.Diagnostics.ProcessStartInfo
$vpnStart.FileName = Join-Path $vpnScratch 'VPNyan.exe'
$vpnStart.Arguments = '--verify-startup "' + $vpnResult + '"'
$vpnStart.WorkingDirectory = $vpnScratch
$vpnStart.UseShellExecute = $false
$vpnStart.CreateNoWindow = $true
foreach ($vpnName in @('DOTNET_ROOT','DOTNET_ROOT_X64','DOTNET_ROOT(x86)')) {
    $vpnStart.EnvironmentVariables[$vpnName] = Join-Path $vpnScratch 'no-installed-dotnet'
}
$vpnStart.EnvironmentVariables['DOTNET_MULTILEVEL_LOOKUP'] = '0'
$vpnStart.EnvironmentVariables['DOTNET_BUNDLE_EXTRACT_BASE_DIR'] = $vpnExtract
$vpnProcess = [Diagnostics.Process]::Start($vpnStart)
try {
    if (!$vpnProcess.WaitForExit(45000)) { $vpnProcess.Kill(); throw 'Portable startup timed out.' }
    if ($vpnProcess.ExitCode -ne 0 -or !(Test-Path -LiteralPath $vpnResult)) {
        throw "Portable startup failed (exit $($vpnProcess.ExitCode)). Check $vpnScratch."
    }
    $vpnReport = Get-Content -LiteralPath $vpnResult -Raw | ConvertFrom-Json
    $vpnOwnCoreClr = $vpnReport.CoreClrPath -eq $vpnStart.FileName -or
        $vpnReport.CoreClrPath.StartsWith(($vpnExtract + '\'), [StringComparison]::OrdinalIgnoreCase)
    if (!$vpnReport.Verified -or !$vpnReport.CoreLibBundled -or !$vpnOwnCoreClr -or
        !$vpnReport.WpfNativePath.StartsWith(($vpnExtract + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The application did not load its own bundled .NET runtime.'
    }
    Write-Output "Portable startup OK: WPF rendered, engine verified, bundled $($vpnReport.Runtime)."
}
finally { $vpnProcess.Dispose() }
