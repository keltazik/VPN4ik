param(
    [string]$Version = '1.0.0-beta.1',
    [string]$BuildDirectory = 'artifacts\VPN4ik-routing'
)
$ErrorActionPreference = 'Stop'
$vpnRoot = Split-Path $PSScriptRoot -Parent
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?$') { throw 'Invalid release version.' }
$vpnBuild = [IO.Path]::GetFullPath((Join-Path $vpnRoot $BuildDirectory))
if (!(Test-Path -LiteralPath (Join-Path $vpnBuild 'VPNyan.exe'))) { throw 'Build VPN4ik first.' }
& (Join-Path $PSScriptRoot 'verify-runtime.ps1') -BuildDirectory $BuildDirectory
$vpnRelease = Join-Path $vpnRoot 'release'
$vpnStaging = Join-Path $vpnRelease ('staging\' + $Version + '\VPN4ik')
if (Test-Path -LiteralPath $vpnStaging) { Remove-Item -LiteralPath $vpnStaging -Recurse -Force }
New-Item -ItemType Directory -Force -Path $vpnStaging | Out-Null
Copy-Item -Path (Join-Path $vpnBuild '*') -Destination $vpnStaging -Recurse -Force
Copy-Item -LiteralPath (Join-Path $vpnRoot 'licenses') -Destination $vpnStaging -Recurse -Force
foreach ($vpnDocument in @('README.md', 'THIRD_PARTY.md', 'CHANGELOG.md')) {
    Copy-Item -LiteralPath (Join-Path $vpnRoot $vpnDocument) -Destination $vpnStaging -Force
}
@'
VPN4ik for Windows x64

1. Extract the whole VPN4ik folder.
2. Start VPNyan.exe. Keep Engine and the other files next to it.
3. Add your subscription and select a server.
4. Click the ornament to connect. Windows requests administrator approval for TUN.

Russian guide: https://github.com/keltazik/VPN4ik
No subscription or VPN keys are included.
'@ | Set-Content -LiteralPath (Join-Path $vpnStaging 'START-HERE.txt') -Encoding utf8
$vpnForbidden = Get-ChildItem -LiteralPath $vpnStaging -Recurse -File | Where-Object {
    $_.Extension -in @('.conf','.dpapi','.pem','.pfx','.key') -or $_.Name -in @('settings.json','activity.dpapi','subscriptions.dpapi')
}
if ($vpnForbidden) { throw 'User data found in release staging.' }
$vpnArchiveName = "VPN4ik-v$Version-windows-x64.zip"
$vpnArchive = Join-Path $vpnRelease $vpnArchiveName
Compress-Archive -LiteralPath $vpnStaging -DestinationPath $vpnArchive -CompressionLevel Optimal -Force
$vpnHash = (Get-FileHash -LiteralPath $vpnArchive -Algorithm SHA256).Hash.ToLowerInvariant()
"$vpnHash  $vpnArchiveName" | Set-Content -LiteralPath (Join-Path $vpnRelease 'SHA256SUMS.txt') -Encoding ascii
Write-Output "Ready: $vpnArchiveName"
Write-Output "SHA256: $vpnHash"
