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
    pub pid: usize,
    pub ppid: usize,
    pub image_file_name: [u16; COSMOS_MAX_PATH],
}

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

    if device.clone()?.is_invalid() {
        return Err(Error::last_os_error().into());
    }

    let mut buffer = vec![COSMOS_PROC_INFO::default(); MAX_PROCESSES];
    let struct_size = size_of::<COSMOS_PROC_INFO>();

    let result = unsafe {
        DeviceIoControl(
            device?,
            IOCTL_COSMOS_DUMP_PROCESSES,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            (buffer.len() * struct_size) as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    result.map_err(|e| {
        eprintln!("DeviceIoControl failed: {e}");
        e
    })?;

    if bytes_returned as usize % struct_size != 0 {
        panic!(
            "Misaligned data: returned {} bytes, expected multiple of {}",
            bytes_returned, struct_size
        );
    }

    let count = bytes_returned as usize / struct_size;
    if count > buffer.len() {
        panic!(
            "Driver returned more entries ({}) than buffer capacity ({})",
            count,
            buffer.len()
        );
    }

    println!(
        "Returned {} bytes for {} entries (struct size = {})",
        bytes_returned, count, struct_size
    );

    for proc in &buffer[..count] {
        let name_end = proc
            .image_file_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(COSMOS_MAX_PATH);
        let raw_name = String::from_utf16(&proc.image_file_name[..name_end])
            .unwrap_or_else(|_| "<Invalid UTF-16>".to_string());

        let display_name = if raw_name.len() > 100 {
            format!("{}...", &raw_name[..97])
        } else {
            raw_name
        };

        println!(
            "PID: {:>6} | PPID: {:>6} | Image: {}",
            proc.pid, proc.ppid, display_name
        );
    }

    Ok(())
}
