param(
    [string]$Version = '1.0.0',
    [string]$BuildDirectory = 'artifacts\VPN4ik-1.0.0'
)
$ErrorActionPreference = 'Stop'
$vpnRoot = Split-Path $PSScriptRoot -Parent
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?$') { throw 'Invalid release version.' }
$vpnBuild = [IO.Path]::GetFullPath((Join-Path $vpnRoot $BuildDirectory))
if (!(Test-Path -LiteralPath (Join-Path $vpnBuild 'VPNyan.exe'))) { throw 'Build VPN4ik first.' }
$vpnBinaryVersion=(Get-Item -LiteralPath (Join-Path $vpnBuild 'VPNyan.exe')).VersionInfo.ProductVersion.Split('+')[0]
if($vpnBinaryVersion -ne $Version) { throw "Build version $vpnBinaryVersion does not match requested release $Version." }
& (Join-Path $vpnRoot 'checks\check-portable.ps1') -BuildDirectory $vpnBuild
$vpnRelease = Join-Path $vpnRoot 'release'
$vpnStaging = Join-Path $vpnRelease ('staging\' + $Version + '\' + [Guid]::NewGuid().ToString('N') + '\VPN4ik')
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
   .NET Desktop Runtime is bundled inside VPNyan.exe; no separate download is needed.
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
$vpnCommit = (& git -C $vpnRoot rev-parse HEAD).Trim()
$vpnMetadata=@{}
$vpnMetadataPath=Join-Path $vpnBuild 'BUILD-INFO.json'
if(Test-Path -LiteralPath $vpnMetadataPath) {
    $vpnPrevious=Get-Content -LiteralPath $vpnMetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach($vpnProperty in $vpnPrevious.PSObject.Properties) {$vpnMetadata[$vpnProperty.Name]=$vpnProperty.Value}
}
$vpnReleaseMetadata=@{
    Version = $Version
    SourceCommit = $vpnCommit
    Architecture = 'windows-x64'
    DotNetBundled = $true
    ExecutableSHA256 = (Get-FileHash -LiteralPath (Join-Path $vpnBuild 'VPNyan.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    XraySHA256 = (Get-FileHash -LiteralPath (Join-Path $vpnBuild 'Engine\xray.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    WorkingTreeDirty = @(& git -C $vpnRoot status --porcelain).Count -gt 0
}
foreach($vpnName in $vpnReleaseMetadata.Keys) {$vpnMetadata[$vpnName]=$vpnReleaseMetadata[$vpnName]}
$vpnMetadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $vpnStaging 'BUILD-INFO.json') -Encoding utf8
$vpnArchive = Join-Path $vpnRelease $vpnArchiveName
Compress-Archive -LiteralPath $vpnStaging -DestinationPath $vpnArchive -CompressionLevel Optimal -Force
$vpnHash = (Get-FileHash -LiteralPath $vpnArchive -Algorithm SHA256).Hash.ToLowerInvariant()
"$vpnHash  $vpnArchiveName" | Set-Content -LiteralPath (Join-Path $vpnRelease 'SHA256SUMS.txt') -Encoding ascii
"$vpnHash  $vpnArchiveName" | Set-Content -LiteralPath ($vpnArchive+'.sha256') -Encoding ascii
Write-Output "Ready: $vpnArchiveName"
Write-Output "SHA256: $vpnHash"
