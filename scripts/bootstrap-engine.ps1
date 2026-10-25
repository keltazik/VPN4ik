$ErrorActionPreference = 'Stop'
$vpnRoot = Split-Path $PSScriptRoot -Parent
$vpnEnginePath = Join-Path $vpnRoot 'source\VPNyan\VPNyan\Engine'
$vpnCache = Join-Path $vpnRoot '.checks-data'
New-Item -ItemType Directory -Force -Path $vpnCache, $vpnEnginePath | Out-Null
$vpnArchive = Join-Path $vpnCache 'Xray-windows-64-v26.10.21.zip'
$vpnExpected = 'FC58C39EE2F2717B4C54D28D374362389E5319B20AE44AEA76EA45A5243EC827'
if (!(Test-Path -LiteralPath $vpnArchive) -or (Get-FileHash -LiteralPath $vpnArchive -Algorithm SHA256).Hash -ne $vpnExpected) {
    Invoke-WebRequest -Uri 'https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-windows-64.zip' -OutFile $vpnArchive -TimeoutSec 120
}
if ((Get-FileHash -LiteralPath $vpnArchive -Algorithm SHA256).Hash -ne $vpnExpected) { throw 'Official Xray archive hash mismatch.' }
Expand-Archive -LiteralPath $vpnArchive -DestinationPath $vpnEnginePath -Force
$vpnDriver = Join-Path $vpnEnginePath 'wintun.dll'
if ((Get-AuthenticodeSignature -LiteralPath $vpnDriver).Status -ne 'Valid') { throw 'Wintun signature is not valid.' }
Write-Output 'Official Xray 26.10.21 and signed Wintun are ready.'
