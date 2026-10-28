$ErrorActionPreference = 'Stop'
$vpnRoot = Split-Path $PSScriptRoot -Parent
$vpnDestination = Join-Path $vpnRoot 'source\VPNyan\VPNyan\Engine\Hiddify'
$vpnScratch = Join-Path $vpnRoot '.tools\hiddify-v5.0.3'
$vpnHashes = @{
    'HiddifyCli.exe'='90948CC26D38307C02A733F8392F68CF148533888462B45CD112755C35FE265C'
    'hiddify-core.dll'='26B82248A8F414DDD78B8306AF5674AB21BF611B26B201B32B560065111EB2B1'
    'libcronet.dll'='3217C6260FBCA5F16072E0B79735742F40109A63BB0FF88FD6B96DD6B54A2928'
}
New-Item -ItemType Directory -Force -Path $vpnScratch,$vpnDestination | Out-Null
$vpnArchive = Join-Path $vpnScratch 'native.tar.gz'
$vpnArchiveHash = '645EF71FB7E6E51CDD8B29B43C9DDEA241B2324DCF441DF7210D3332E39F2443'
if (!(Test-Path -LiteralPath $vpnArchive) -or (Get-FileHash -LiteralPath $vpnArchive).Hash -ne $vpnArchiveHash) {
    Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/hiddify/hiddify-core/releases/download/v5.0.3/hiddify-lib-windows-amd64.tar.gz' -OutFile $vpnArchive
}
if ((Get-FileHash -LiteralPath $vpnArchive).Hash -ne $vpnArchiveHash) { throw 'Hiddify release archive checksum mismatch.' }
Copy-Item -LiteralPath $vpnArchive -Destination (Join-Path $vpnDestination 'native.tar.gz') -Force
$vpnEntries = @(& tar -tzf $vpnArchive)
foreach ($vpnEntry in $vpnEntries) { if (!$vpnHashes.ContainsKey(($vpnEntry -replace '^\./',''))) { throw 'Unexpected Hiddify archive entry.' } }
& tar -xzf $vpnArchive -C $vpnScratch
if ($LASTEXITCODE -ne 0) { throw 'Hiddify extraction failed.' }
foreach ($vpnFile in $vpnHashes.Keys) {
    $vpnPath = Join-Path $vpnScratch $vpnFile
    if ((Get-FileHash -LiteralPath $vpnPath).Hash -ne $vpnHashes[$vpnFile]) { throw 'Hiddify binary checksum mismatch.' }
    Copy-Item -LiteralPath $vpnPath -Destination (Join-Path $vpnDestination $vpnFile) -Force
}
$vpnWintun = Join-Path $vpnRoot 'source\VPNyan\VPNyan\Engine\wintun.dll'
if ((Get-FileHash -LiteralPath $vpnWintun).Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE') { throw 'Wintun checksum mismatch.' }
Copy-Item -LiteralPath $vpnWintun -Destination (Join-Path $vpnDestination 'wintun.dll') -Force
$vpnLicense = Join-Path $vpnRoot 'licenses\Hiddify-Core.txt'
if (!(Test-Path -LiteralPath $vpnLicense)) { throw 'Hiddify license notice missing.' }
Copy-Item -LiteralPath $vpnLicense -Destination (Join-Path $vpnDestination 'LICENSE.txt') -Force
Write-Output 'Verified official Hiddify Core 5.0.3 (Windows x64).'
