# Sign Compiled Cosmos Driver
# Run as Administrator

# Parameters - Update the path if necessary
$certName = "CosmosDriverCert"
$certPassword = "Test123!"
$driverPath = "C:\Users\ta1on\source\repos\Cosmos\x64\Debug\Cosmos.sys"
$certPath = "C:\Temp\CosmosDriverCerts"

# Create directory if needed
if (!(Test-Path $certPath)) {
    New-Item -ItemType Directory -Path $certPath | Out-Null
    Write-Host "Created directory: $certPath" -ForegroundColor Green
}

# Check if driver exists
if (!(Test-Path $driverPath)) {
    Write-Host "Driver not found at: $driverPath" -ForegroundColor Red
    Write-Host "Please update the path and run again." -ForegroundColor Red
    exit
}

# Create self-signed certificate
Write-Host "Creating certificate..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=$certName" -KeyUsage DigitalSignature -FriendlyName "$certName" -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

$thumbprint = $cert.Thumbprint
Write-Host "Certificate created with thumbprint: $thumbprint" -ForegroundColor Green

# Export to PFX
$securePassword = ConvertTo-SecureString -String $certPassword -Force -AsPlainText
$pfxPath = Join-Path $certPath "$certName.pfx"
Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$thumbprint" -FilePath $pfxPath -Password $securePassword | Out-Null

# Export to CER
$cerPath = Join-Path $certPath "$certName.cer"
Export-Certificate -Cert "Cert:\LocalMachine\My\$thumbprint" -FilePath $cerPath | Out-Null

# Sign the driver
Write-Host "Signing driver..." -ForegroundColor Cyan
signtool sign /fd SHA256 /f $pfxPath /p $certPassword /tr http://timestamp.digicert.com /td SHA256 $driverPath

# Verify signature
Write-Host "Verifying signature..." -ForegroundColor Cyan
signtool verify /pa $driverPath

Write-Host "`nCertificate files saved to: $certPath" -ForegroundColor Green
Write-Host "`nCopy these files to your VM:" -ForegroundColor Yellow
Write-Host "1. $cerPath" -ForegroundColor Yellow
Write-Host "2. $driverPath (signed)" -ForegroundColor Yellow