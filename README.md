# Cosmos XDR - Advanced Windows Process Monitoring System

**Cosmos** is the base project for Extended Detection and Response (XDR) solution for Windows, The XDR part will be pushed later on, consisting of a secure kernel driver and modern Rust-based userland client. Currerntly the user space part is written in Rust however it can be written in any language. It provides comprehensive real-time process, thread, and image monitoring capabilities for security research, malware analysis, and system behavior monitoring.

##  Architecture Overview

```

                    USERLAND (Ring 3)                       

  CosmosGuard (Rust Client)                                 
   Real-time Process Monitoring                          
   IOCTL Communication                                   
   Process Deduplication                                 

                       DeviceIoControl()
                       \\.\CosmosLink

                    KERNEL (Ring 0)                         

  Cosmos.sys (Kernel Driver)                                
   PsSetLoadImageNotifyRoutine()                         
   PsSetCreateProcessNotifyRoutine()                     
   PsSetCreateThreadNotifyRoutine()                      
   Secure IOCTL Interface                                
   Process Hash Table Tracking                           

```

##  Security Features

- **Restricted Device Access**: SDDL permissions limit access to Administrators and SYSTEM only
- **Secure Device Creation**: Uses `IoCreateDeviceSecure` with proper permission enforcement
- **Code Signing**: Includes automated certificate generation and driver signing scripts
- **Buffer Validation**: Comprehensive input validation for all IOCTL operations
- **Memory Safety**: Rust userland client prevents common memory vulnerabilities

##  Key Features

### Kernel Driver (Cosmos.sys)
- **Multi-Source Process Detection**: Combines multiple Windows notification mechanisms
- **Short-Lived Process Capture**: Detects ephemeral processes often missed by traditional monitoring
- **Real-Time Event Processing**: Low-latency notification callbacks
- **Secure Communication**: Protected IOCTL interface for userland communication
- **Comprehensive Cleanup**: Proper resource management and unload procedures

### Userland Client (CosmosGuard)
- **Real-Time Monitoring**: 200ms polling interval for responsive detection
- **Process Deduplication**: Prevents duplicate event reporting
- **Cross-Platform Rust**: Memory-safe implementation with Windows API bindings
- **Detailed Process Information**: PID, PPID, image path, memory layout, and capture source
- **Error Resilience**: Robust error handling and connection recovery

##  System Requirements

- **Operating System**: Windows 10/11 (x64 or ARM64)
- **Privileges**: Administrator rights required
- **Development**: 
  - Visual Studio 2022 with Windows Driver Kit (WDK)
  - Rust toolchain for userland client
  - Windows SDK 10.0.26100.1 or later

##  Building the Project

### Prerequisites
1. Install Visual Studio 2022 with C++ workload
2. Install Windows Driver Kit (WDK) via NuGet or installer
3. Install Rust: `winget install Rustlang.Rust.MSVC`

### Build Kernel Driver
```cmd
# Open Developer Command Prompt as Administrator
cd code/Cosmos
msbuild Cosmos.sln /p:Configuration=Release /p:Platform=x64
```

### Build Userland Client
```cmd
cd code/Cosmos/cosmosguard
cargo build --release
```

### Sign Driver (Required for Loading)
```powershell
# Run as Administrator
.\GenerateCertAndSelfSignCompiledCosmos.ps1
```

##  Installation & Usage

### 1. Install Driver Certificate
```cmd
# Install self-signed certificate (development/testing only)
certlm.msc
# Import CosmosDriverCert.cer to "Trusted Root Certification Authorities"
```

### 2. Enable Test Signing (if using self-signed certificate)
```cmd
# Run as Administrator
bcdedit /set testsigning on
# Reboot required
```

### 3. Install Driver
```cmd
# Method 1: Using Device Manager
# Add Legacy Hardware -> Install from disk -> Select Cosmos.inf

# Method 2: Using sc.exe
sc create Cosmos binPath= "C:\path\to\Cosmos.sys" type= kernel
sc start Cosmos
```

### 4. Run Monitoring Client
```cmd
# Run as Administrator
.\cosmosguard.exe
```

##  Sample Output

```
CosmosGuard - Real-time Process Monitor
========================================
Connecting to Cosmos kernel driver...

PID:   1234 | PPID:    456 | Base: 0x7ff6abc00000 | Size: 0x12000 | Source: ImageLoad    | Image: C:\Windows\System32\notepad.exe
PID:   5678 | PPID:   1234 | Base: 0x7ff7def00000 | Size: 0x8000  | Source: CreateNotify | Image: C:\Windows\System32\cmd.exe
PID:   9012 | PPID:   5678 | Base: 0x0            | Size: 0x0     | Source: CreateNotify | Image: C:\temp\malware.exe
```

##  Capture Sources Explained

| Source | Description | Use Case |
|--------|-------------|----------|
| `ImageLoad` | Detected via `PsSetLoadImageNotifyRoutine()` | Primary detection - full image information |
| `CreateNotify` | Detected via `PsSetCreateProcessNotifyRoutine()` | Backup detection - parent-child relationships |
| `LocateFallback` | Detected via `SeLocateProcessImageName()` | Last resort - EPROCESS structure parsing |

##  Development Status

###  Implemented
- [x] Secure kernel driver with WDM architecture
- [x] Multi-source process tracking and deduplication
- [x] IOCTL-based kernel-userland communication
- [x] Rust userland client with real-time monitoring
- [x] Automated driver signing and certificate generation
- [x] Comprehensive error handling and cleanup

###  In Progress
- [ ] Thread-level monitoring implementation
- [ ] Configuration file support for userland client
- [ ] Event filtering and rule-based alerting
- [ ] Performance optimization and profiling

###  Planned Features
- [ ] ETW (Event Tracing for Windows) integration
- [ ] Network connection monitoring
- [ ] File system activity tracking
- [ ] Registry access monitoring
- [ ] Advanced behavioral analysis

##  Troubleshooting

### Driver Won't Load
```cmd
# Check driver signing status
signtool verify /pa Cosmos.sys

# Verify certificate installation
certlm.msc

# Check test signing mode
bcdedit /enum {current}
```

### Access Denied Errors
```cmd
# Ensure running as Administrator
whoami /groups | findstr "S-1-5-32-544"

# Check SDDL permissions
```

### Communication Failures
```cmd
# Verify symbolic link exists
dir \\.\CosmosLink

# Check driver status
sc query Cosmos
```

##  License

MIT License - See [LICENSE](LICENSE) file for details.

##  Security Disclaimer

**This software is intended for security research, malware analysis, and educational purposes only.** 

- Self-signed drivers reduce system security and should only be used in isolated test environments
- Production deployments require Microsoft-signed drivers or WHQL certification
- The authors are not responsible for any system damage or security vulnerabilities
- Always test in virtual machines before deploying on production systems

##  Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-monitoring`)
3. Commit your changes (`git commit -am 'Add new monitoring capability'`)
4. Push to the branch (`git push origin feature/new-monitoring`)
5. Create a Pull Request

##  References

- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [SDDL Security Descriptors](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [Process and Thread Notifications](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/process-and-thread-manager-routines)
- [Rust Windows API Bindings](https://github.com/microsoft/windows-rs)

---

**Author**: Udi Shamir  
**Copyright**:  2024 - 2025 Udi Shamir. All Rights Reserved.
