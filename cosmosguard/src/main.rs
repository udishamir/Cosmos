use std::ffi::OsStr;
use std::io::Error;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use windows::{
    Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    },
    core::*,
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CosmosInfo {
    pid: u32,
    image_name: [u8; 64],
}

const COSMOS_MAX_PATH: usize = 260;
const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0x0;
const FILE_ANY_ACCESS: u32 = 0x0;
const MAX_PROCESSES: usize = 128;
const IOCTL_COSMOS_DUMP_PROCESSES: u32 =
    (FILE_DEVICE_UNKNOWN << 16) | (0x801 << 2) | METHOD_BUFFERED | (FILE_ANY_ACCESS << 14);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct COSMOS_PROC_INFO {
    pub pid: usize,                              // ULONG_PTR → usize (matches 32/64-bit)
    pub ppid: usize,                             // ULONG_PTR → usize
    pub image_file_name: [u16; COSMOS_MAX_PATH], // WCHAR buffer
}

// Optional: zero-initialized helper
impl Default for COSMOS_PROC_INFO {
    fn default() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            image_file_name: [0u16; COSMOS_MAX_PATH],
        }
    }
}

fn to_utf16(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn main() -> Result<()> {
    let mut bytes_returned: u32 = 0;

    let device_path = to_utf16(r"\\.\CosmosLink");
    let device = unsafe {
        CreateFileW(
            PCWSTR(device_path.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    if device.clone()?.clone().is_invalid() {
        return Err(Error::last_os_error().into());
    }

    let mut buffer = vec![
        CosmosInfo {
            pid: 0,
            image_name: [0; 64],
        };
        MAX_PROCESSES
    ];

    // ✅ DeviceIoControl now returns Result<(), Error>
    let result = unsafe {
        DeviceIoControl(
            device?,
            IOCTL_COSMOS_DUMP_PROCESSES,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            size_of::<CosmosInfo>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    // Handle the result properly
    result.map_err(|e| {
        eprintln!("DeviceIoControl failed: {e}");
        e
    })?;

    let count = bytes_returned as usize / std::mem::size_of::<CosmosInfo>();
    for proc in &buffer[..count] {
        let name_end = proc.image_name.iter().position(|&c| c == 0).unwrap_or(64);
        let image_name = String::from_utf8_lossy(&proc.image_name[..name_end]);
        println!("PID: {:>5} | Image: {}", proc.pid, image_name);
    }

    Ok(())
}
