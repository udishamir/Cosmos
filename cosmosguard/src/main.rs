/*
    CosmosGuard Very simple process monitoring using Cosmos Driver
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

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct COSMOS_PROC_INFO {
    pid: usize,
    ppid: usize,
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

        let count = bytes_returned as usize / std::mem::size_of::<COSMOS_PROC_INFO>();
        for proc in &buffer[..count] {
            if seen_pids.insert(proc.pid) {
                let end = proc
                    .image_file_name
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(COSMOS_MAX_PATH);
                let name = String::from_utf16_lossy(&proc.image_file_name[..end]);
                println!(
                    "PID: {:>6} | PPID: {:>6} | Image: {}",
                    proc.pid, proc.ppid, name
                );
            }
        }

        thread::sleep(Duration::from_millis(200));
    }

    // `device` is dropped automatically here
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CosmosGuard starting process monitor ...");

    let handle = thread::spawn(poll_driver_loop);

    // Wait for thread to finish
    handle.join().unwrap();
    Ok(())
}
