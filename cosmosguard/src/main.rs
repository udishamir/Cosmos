/*
    Cosmos XDR

    © 2024–2025 Udi Shamir. All Rights Reserved.
    Unauthorized copying of this file, via any medium, is strictly prohibited.
    Proprietary and confidential.

    Author: Udi Shamir
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

const COSMOS_MAX_PATH: usize = 260;
const MAX_PROCESSES: usize = 128;
const FILE_ANY_ACCESS: u32 = 0;
const IOCTL_COSMOS_DUMP_PROCESSES: u32 =
    (FILE_DEVICE_UNKNOWN << 16) | (0x801 << 2) | METHOD_BUFFERED | (FILE_ANY_ACCESS << 14);

const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0x0;

// Creationg Source
#[repr(u32)]
#[derive(Debug)]
pub enum CaptureSource {
    None = 0,
    CreateNotify = 1,
    ImageLoad = 2,
    LocateFallback = 3,
    Unknown = 9999,
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

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct COSMOS_PROC_INFO {
    pid: u32,
    ppid: u32,
    image_base: u64,
    image_size: u64,
    capture_source: u32,
    image_file_name: [u16; COSMOS_MAX_PATH],
}

struct SafeHandle(HANDLE);
impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        };
    }
}

fn to_utf16<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

fn poll_driver_loop() {
    let device: SafeHandle;

    let path = to_utf16(r"\\.\CosmosLink");

    device = match unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0xC000_0000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    } {
        Ok(h) => SafeHandle(h),
        Err(e) => {
            eprintln!("Failed to open CosmosLink device: {}", e);
            return;
        }
    };

    let mut seen_pids = HashSet::new();

    loop {
        let mut buffer = vec![
            COSMOS_PROC_INFO {
                pid: 0,
                ppid: 0,
                image_base: 0,
                image_size: 0,
                capture_source: 0,
                image_file_name: [0u16; COSMOS_MAX_PATH],
            };
            MAX_PROCESSES
        ];

        let mut bytes_returned = 0;

        let result = unsafe {
            DeviceIoControl(
                device.0,
                IOCTL_COSMOS_DUMP_PROCESSES,
                None,
                0,
                Some(buffer.as_mut_ptr() as *mut _),
                (buffer.len() * std::mem::size_of::<COSMOS_PROC_INFO>()) as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if let Err(e) = result {
            eprintln!("DeviceIoControl failed: {}", e);
            break;
        }

        if bytes_returned == 0 {
            eprintln!("DeviceIoControl returned 0 bytes.");
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        let count = bytes_returned as usize / std::mem::size_of::<COSMOS_PROC_INFO>();
        for proc in &buffer[..count] {
            if seen_pids.insert(proc.pid) {
                let end = proc
                    .image_file_name
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(COSMOS_MAX_PATH);

                let name = String::from_utf16_lossy(&proc.image_file_name[..end]);

                let source = CaptureSource::from(proc.capture_source);

                println!(
                    "PID: {:>6} | PPID: {:>6} | Base: {:#x} | Size: {:#x} | Source: {:?} | Image: {}",
                    proc.pid, proc.ppid, proc.image_base, proc.image_size, source, name
                );

                // DEBUG, need to make sure its the same size as the COSMOS_PROC_INFO in kernel
                println!(
                    "Rust COSMOS_PROC_INFO size = {}",
                    std::mem::size_of::<COSMOS_PROC_INFO>()
                );

                println!(
                    "PID: {:>6} | PPID: {:>6} | ImageBase: {:#x} | ImageSize: {:#x} | Source: {:?} | Image: {}",
                    proc.pid,
                    proc.ppid,
                    proc.image_base,
                    proc.image_size,
                    proc.capture_source,
                    name
                );
            }
        }

        thread::sleep(Duration::from_millis(200));
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CosmosGuard starting process monitor ...");

    let handle = thread::spawn(poll_driver_loop);

    // Wait for thread to finish
    handle.join().unwrap();
    Ok(())
}
