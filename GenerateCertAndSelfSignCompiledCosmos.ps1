# Cosmos Driver Code Signing Script
# 
# Purpose: Generates self-signed certificate and signs the compiled Cosmos driver
#          for testing and development purposes. Self-signed drivers require
#          test mode or certificate installation for loading.
#
# Prerequisites:
#   1. Run as Administrator (required for certificate store access)
#   2. Driver must be compiled (Cosmos.sys exists)
#   3. SignTool.exe available in PATH (Windows SDK component)
#
# Security Warning: 
#   - Self-signed certificates are for DEVELOPMENT/TESTING only
#   - Production drivers require certificates from trusted CA
#   - Test password is exposed in script - change for production use
#
# Usage:
#   1. Update $driverPath to match your build output location
#   2. Run PowerShell as Administrator
#   3. Execute script: .\GenerateCertAndSelfSignCompiledCosmos.ps1

# Configuration Parameters - MODIFY THESE FOR YOUR ENVIRONMENT
$certName = "CosmosDriverCert"                                          # Certificate subject name
$certPassword = "Test123!"                                              # Certificate password (CHANGE FOR PRODUCTION)
$driverPath = "C:\Users\ta1on\source\repos\Cosmos\x64\Debug\Cosmos.sys" # Path to compiled driver
$certPath = "C:\Temp\CosmosDriverCerts"                                 # Directory for certificate files

# Step 1: Setup certificate storage directory
Write-Host "=== Cosmos Driver Signing Process ===" -ForegroundColor Cyan
Write-Host "Step 1: Setting up certificate directory..." -ForegroundColor Yellow

if (!(Test-Path $certPath)) {
    New-Item -ItemType Directory -Path $certPath | Out-Null
    Write-Host "Created directory: $certPath" -ForegroundColor Green
} else {
    Write-Host "Using existing directory: $certPath" -ForegroundColor Green
}

# Step 2: Validate driver file exists
Write-Host "Step 2: Validating driver file..." -ForegroundColor Yellow

if (!(Test-Path $driverPath)) {
    Write-Host "ERROR: Driver not found at: $driverPath" -ForegroundColor Red
    Write-Host "Please ensure:" -ForegroundColor Red
    Write-Host "  1. Driver has been compiled successfully" -ForegroundColor Red
    Write-Host "  2. Build configuration matches the path (Debug/Release, x64/ARM64)" -ForegroundColor Red
    Write-Host "  3. Update `$driverPath variable in this script if needed" -ForegroundColor Red
    Write-Host "Current build should produce: Cosmos.sys" -ForegroundColor Red
    exit 1
}
Write-Host "Driver found: $driverPath" -ForegroundColor Green

# Step 3: Create self-signed code signing certificate
Write-Host "Step 3: Creating self-signed certificate..." -ForegroundColor Yellow

# Create certificate with code signing capabilities
# TextExtension parameters:
#   2.5.29.37 = Enhanced Key Usage (EKU) - specifies code signing
#   2.5.29.19 = Basic Constraints - marks as end-entity certificate
$cert = New-SelfSignedCertificate `
    -Type Custom `
    -Subject "CN=$certName" `
    -KeyUsage DigitalSignature `
    -FriendlyName "$certName - Cosmos Driver Development Certificate" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

$thumbprint = $cert.Thumbprint
Write-Host "Certificate created successfully!" -ForegroundColor Green
Write-Host "  Subject: CN=$certName" -ForegroundColor White
Write-Host "  Thumbprint: $thumbprint" -ForegroundColor White
Write-Host "  Store Location: Local Machine Personal Store" -ForegroundColor White

# Step 4: Export certificate files for distribution and installation
Write-Host "Step 4: Exporting certificate files..." -ForegroundColor Yellow

# Export to PFX (Personal Information Exchange) format
# Contains both private and public key - used for signing
$securePassword = ConvertTo-SecureString -String $certPassword -Force -AsPlainText
$pfxPath = Join-Path $certPath "$certName.pfx"
Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$thumbprint" -FilePath $pfxPath -Password $securePassword | Out-Null
Write-Host "  PFX exported: $pfxPath" -ForegroundColor White

# Export to CER (Certificate) format  
# Contains only public key - used for installation on target systems
$cerPath = Join-Path $certPath "$certName.cer"
Export-Certificate -Cert "Cert:\LocalMachine\My\$thumbprint" -FilePath $cerPath | Out-Null
Write-Host "  CER exported: $cerPath" -ForegroundColor White

# Step 5: Sign the driver binary
Write-Host "Step 5: Signing driver with certificate..." -ForegroundColor Yellow

# Sign using SignTool with the following parameters:
#   /fd SHA256           - File digest algorithm (SHA256 for security)
#   /f <pfx>            - Certificate file to use for signing
#   /p <password>       - Password for PFX file
#   /tr <url>           - Timestamp server URL (proves signing time)
#   /td SHA256          - Timestamp digest algorithm
Write-Host "  Signing with SHA256 algorithm and timestamp..." -ForegroundColor White

$signResult = & signtool sign /fd SHA256 /f $pfxPath /p $certPassword /tr http://timestamp.digicert.com /td SHA256 $driverPath

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Driver signed successfully!" -ForegroundColor Green
} else {
    Write-Host "  ERROR: Driver signing failed!" -ForegroundColor Red
    Write-Host "  Ensure SignTool.exe is available in PATH (Windows SDK)" -ForegroundColor Red
    exit 1
}

# Step 6: Verify driver signature
Write-Host "Step 6: Verifying driver signature..." -ForegroundColor Yellow

# Verify signature using SignTool
#   /pa - Verify against all certificate policies (including self-signed)
$verifyResult = & signtool verify /pa $driverPath

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Signature verification: PASSED" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Signature verification failed" -ForegroundColor Yellow
    Write-Host "  This is expected for self-signed certificates on non-dev systems" -ForegroundColor Yellow
}

# Step 7: Summary and next steps
Write-Host "`n=== SIGNING COMPLETE ===" -ForegroundColor Green
Write-Host "Certificate files saved to: $certPath" -ForegroundColor Green
Write-Host "Signed driver available at: $driverPath" -ForegroundColor Green

Write-Host "`n=== NEXT STEPS FOR TESTING ===" -ForegroundColor Cyan
Write-Host "For VM or test system deployment:" -ForegroundColor Yellow
Write-Host "1. Copy certificate file: $cerPath" -ForegroundColor White
Write-Host "2. Copy signed driver: $driverPath" -ForegroundColor White
Write-Host "3. Install certificate on target system:" -ForegroundColor White
Write-Host "   - Right-click $certName.cer -> Install Certificate" -ForegroundColor Gray
Write-Host "   - Store Location: Local Machine" -ForegroundColor Gray
Write-Host "   - Certificate Store: Trusted Root Certification Authorities" -ForegroundColor Gray
Write-Host "4. Enable test signing (if needed):" -ForegroundColor White
Write-Host "   - Run as Admin: bcdedit /set testsigning on" -ForegroundColor Gray
Write-Host "   - Reboot system" -ForegroundColor Gray
Write-Host "5. Install driver using Device Manager or sc.exe" -ForegroundColor White

Write-Host "`n=== SECURITY NOTES ===" -ForegroundColor Red
Write-Host "- Self-signed certificates are for DEVELOPMENT/TESTING only" -ForegroundColor Yellow
Write-Host "- Production systems require Microsoft-signed or WHQL drivers" -ForegroundColor Yellow
Write-Host "- Test signing reduces system security - disable after testing" -ForegroundColor Yellow