/*
    Cosmos XDR - Userland Monitor Client

     20242025 Udi Shamir. All Rights Reserved.
    Unauthorized copying of this file, via any medium, is strictly prohibited.
    Proprietary and confidential.

    Author: Udi Shamir
    
    Purpose: Real-time Windows process monitoring client that communicates with
             the Cosmos kernel driver via IOCTL interface.
             
    Architecture:
    - Connects to kernel driver via symbolic link "\\.\CosmosLink"
    - Polls driver every 200ms for new process information
    - Deduplicates processes using HashSet to prevent repeated output
    - Displays process details including PID, PPID, image path, and capture source
    
    Security: Requires Administrator privileges to access the kernel driver
*/

use std::{collections::HashSet, ffi::OsStr, os::windows::ffi::OsStrExt, thread, time::Duration};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    },
    core::PCWSTR,
};

// Constants must match kernel driver definitions exactly for binary compatibility
const COSMOS_MAX_PATH: usize = 260;           // Maximum length for image file names (Windows MAX_PATH)
const MAX_PROCESSES: usize = 128;             // Maximum processes to retrieve per IOCTL call
const FILE_ANY_ACCESS: u32 = 0;               // No specific access rights required

// IOCTL code construction using Windows CTL_CODE macro equivalent
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
const IOCTL_COSMOS_DUMP_PROCESSES: u32 =
    (FILE_DEVICE_UNKNOWN << 16) | (0x801 << 2) | METHOD_BUFFERED | (FILE_ANY_ACCESS << 14);

const FILE_DEVICE_UNKNOWN: u32 = 0x00000022; // Standard Windows device type for custom drivers
const METHOD_BUFFERED: u32 = 0x0;             // Kernel allocates and manages I/O buffers

// Process Capture Source - indicates how the kernel driver detected the process
// Must match CAPTURE_SOURCE enum values in kernel driver
#[repr(u32)]
#[derive(Debug)]
pub enum CaptureSource {
    None = 0,           // Process termination or unknown state
    CreateNotify = 1,   // Detected via PsSetCreateProcessNotifyRoutine()
    ImageLoad = 2,      // Detected via PsSetLoadImageNotifyRoutine() 
    LocateFallback = 3, // Detected via SeLocateProcessImageName() fallback
    Unknown = 9999,     // Invalid or corrupted capture source value
}

impl From<u32> for CaptureSource {
    fn from(value: u32) -> Self {
        match value {
            0 => CaptureSource::None,
            1 => CaptureSource::CreateNotify,
            2 => CaptureSource::ImageLoad,
            3 => CaptureSource::LocateFallback,
            _ => CaptureSource::Unknown,
        }
    }
}

// Process information structure - must exactly match COSMOS_PROC_INFO in kernel driver
// Binary layout compatibility is critical for IOCTL communication
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct COSMOS_PROC_INFO {
    pid: u32,                                    // Process ID
    ppid: u32,                                   // Parent Process ID  
    image_base: u64,                             // Base address of process image in memory
    image_size: u64,                             // Size of process image in memory
    capture_source: u32,                         // How the process was detected (see CaptureSource enum)
    image_file_name: [u16; COSMOS_MAX_PATH],     // Full path to executable (UTF-16 null-terminated)
}

// RAII wrapper for Windows HANDLEs - ensures automatic cleanup
// Prevents handle leaks when function exits due to errors or panics
struct SafeHandle(HANDLE);
impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe {
            // Ignore errors on close - handle might already be invalid
            let _ = CloseHandle(self.0);
        };
    }
}

// Convert Rust string to null-terminated UTF-16 for Windows API calls
// Windows APIs expect wide character strings terminated with null
fn to_utf16<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

// Main polling loop - continuously monitors kernel driver for new process events
// Runs indefinitely until error occurs or process is terminated
fn poll_driver_loop() {
    let device: SafeHandle;

    // Convert device path to Windows-compatible UTF-16 format
    // "\\.\CosmosLink" is the symbolic link created by the kernel driver
    let path = to_utf16(r"\\.\CosmosLink");

    // Establish connection to kernel driver via symbolic link
    device = match unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0xC000_0000, // GENERIC_READ | GENERIC_WRITE - full access required for IOCTL
            FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow other processes to access device
            None,        // No security attributes
            OPEN_EXISTING, // Device must already exist (created by driver)
            FILE_ATTRIBUTE_NORMAL, // Standard file attributes
            None,        // No template file
        )
    } {
        Ok(h) => SafeHandle(h),
        Err(e) => {
            eprintln!("Failed to open CosmosLink device: {}", e);
            eprintln!("Ensure:");
            eprintln!("1. Cosmos driver is loaded and running");
            eprintln!("2. Running as Administrator");
            eprintln!("3. Driver symbolic link is properly created");
            return;
        }
    };

    // Process deduplication - track PIDs we've already reported
    // Prevents spamming console with repeated process information
    let mut seen_pids = HashSet::new();

    // Main monitoring loop - polls driver every 200ms for new processes
    loop {
        // Allocate buffer for process information array
        // Initialize with zeros to ensure clean data for each request
        let mut buffer = vec![
            COSMOS_PROC_INFO {
                pid: 0,
                ppid: 0,
                image_base: 0,
                image_size: 0,
                capture_source: 0,
                image_file_name: [0u16; COSMOS_MAX_PATH],
            };
            MAX_PROCESSES // Request up to 128 processes per call
        ];

        let mut bytes_returned = 0;

        // Send IOCTL request to kernel driver to retrieve tracked processes
        let result = unsafe {
            DeviceIoControl(
                device.0,                    // Handle to our driver device
                IOCTL_COSMOS_DUMP_PROCESSES, // Custom IOCTL code for process dump
                None,                        // No input buffer needed
                0,                           // Input buffer size
                Some(buffer.as_mut_ptr() as *mut _), // Output buffer for process data
                (buffer.len() * std::mem::size_of::<COSMOS_PROC_INFO>()) as u32, // Output buffer size
                Some(&mut bytes_returned),   // Actual bytes written by driver
                None,                        // No overlapped I/O
            )
        };

        // Handle IOCTL communication errors
        if let Err(e) = result {
            eprintln!("DeviceIoControl failed: {}", e);
            eprintln!("Driver may have been unloaded or device connection lost");
            break;
        }

        // Handle empty responses (no new processes)
        if bytes_returned == 0 {
            // Normal condition - driver has no new process data
            // Sleep longer to reduce CPU usage when no activity
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        // Calculate number of process entries returned by driver
        let count = bytes_returned as usize / std::mem::size_of::<COSMOS_PROC_INFO>();
        
        // Process each returned entry
        for proc in &buffer[..count] {
            // Only display processes we haven't seen before (deduplication)
            if seen_pids.insert(proc.pid) {
                // Convert UTF-16 image name to Rust string
                // Find null terminator to determine actual string length
                let end = proc
                    .image_file_name
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(COSMOS_MAX_PATH);

                // Convert from UTF-16 to UTF-8, handling invalid characters gracefully
                let name = String::from_utf16_lossy(&proc.image_file_name[..end]);

                // Convert numeric capture source to enum for display
                let source = CaptureSource::from(proc.capture_source);

                // Display formatted process information
                println!(
                    "PID: {:>6} | PPID: {:>6} | Base: {:#x} | Size: {:#x} | Source: {:?} | Image: {}",
                    proc.pid, proc.ppid, proc.image_base, proc.image_size, source, name
                );

                // Debug: Verify structure size matches kernel driver expectations
                // This should be 1048 bytes (4+4+8+8+4+520) for binary compatibility
                if std::mem::size_of::<COSMOS_PROC_INFO>() != 548 {
                    eprintln!(
                        "WARNING: Structure size mismatch! Rust: {}, Expected: 548",
                        std::mem::size_of::<COSMOS_PROC_INFO>()
                    );
                }
            }
        }

        // Poll every 200ms for responsive monitoring without excessive CPU usage
        // Balances real-time detection with system performance
        thread::sleep(Duration::from_millis(200));
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CosmosGuard - Real-time Process Monitor");
    println!("========================================");
    println!("Connecting to Cosmos kernel driver...");
    println!("Press Ctrl+C to stop monitoring");
    println!("");

    // Spawn monitoring thread to handle driver communication
    let handle = thread::spawn(poll_driver_loop);

    // Wait for monitoring thread to complete (on error or termination)
    // In normal operation, this will run indefinitely until killed
    match handle.join() {
        Ok(_) => {
            println!("Monitoring thread completed normally");
        }
        Err(e) => {
            eprintln!("Monitoring thread panicked: {:?}", e);
            return Err("Thread panic".into());
        }
    }
    
    Ok(())
}
