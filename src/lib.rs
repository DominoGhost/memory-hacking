use windows::Win32::{
    System::{
        Threading,
        Diagnostics::{Debug, ToolHelp}},
    Foundation};

use std::{
    mem::{self, MaybeUninit},
    str, ptr};

use core::ffi;

fn print_error(function_call: &str) {
    unsafe {
        let error = Foundation::GetLastError();
        println!("'{}' function had an error with the code: {}", function_call, error.0);
    }
}

fn get_process_name(pe: &ToolHelp::PROCESSENTRY32W) -> String {
    let exe_name = String::from_utf16(&pe.szExeFile).unwrap();
    String::from(exe_name.trim_end_matches('\0'))
}

struct HandleWrapper {
    handle: Foundation::HANDLE
}

impl HandleWrapper {
    fn new(h: Foundation::HANDLE) -> Self {
        Self { 
            handle: h
        }
    }

    fn get_handle(&self) -> Foundation::HANDLE {
        self.handle
    }
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        unsafe {
            let did_handle_close = Foundation::CloseHandle(self.handle);
            if !did_handle_close.as_bool() {
                print_error("CloseHandle");
            }
        }
    }
}

// TODO: Give more details on errors
pub fn get_process_id(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot_handle = HandleWrapper::new(ToolHelp::CreateToolhelp32Snapshot(ToolHelp::TH32CS_SNAPPROCESS, 0).unwrap());
        let mut pe = ToolHelp::PROCESSENTRY32W{ 
            dwSize: mem::size_of::<ToolHelp::PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            th32ParentProcessID: 0,
            th32ProcessID: 0,
            cntThreads: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260]
        };

        let succeded = ToolHelp::Process32FirstW(snapshot_handle.get_handle(), &mut pe);
        if !succeded.as_bool() && Foundation::GetLastError() != Foundation::ERROR_NO_MORE_FILES {
            print_error("Process32FirstW");
            return None;
        } else {
            if get_process_name(&pe) == process_name {
                return Some(pe.th32ProcessID);
            }
        }

        while ToolHelp::Process32NextW(snapshot_handle.get_handle(), &mut pe).as_bool() {
            if get_process_name(&pe) == process_name {
                return Some(pe.th32ProcessID);
            }
        }
        if Foundation::GetLastError() != Foundation::ERROR_NO_MORE_FILES {
            print_error("Process32NextW");
        }
    }
    
    None
}

// TODO: Return an error if memory reading fails. Undefined behavior can occur otherwise until then because of 'assume_init()'
pub fn read_process_memory<T>(pid: u32, address_to_read: *const ffi::c_void) -> T {
    unsafe {
        let mut memory_reading_buffer = MaybeUninit::<T>::uninit();

        let handle = HandleWrapper::new(Threading::OpenProcess(Threading::PROCESS_VM_READ, Foundation::BOOL(0), pid).unwrap());
        let read_succeeded = Debug::ReadProcessMemory(handle.get_handle(), address_to_read, memory_reading_buffer.as_mut_ptr().cast(), mem::size_of::<T>(), ptr::null_mut());

        if !read_succeeded.as_bool() {
            print_error("ReadProcessMemory");
        }

        memory_reading_buffer.assume_init()
    }
}

pub fn write_process_memory(data_to_write: i32, pid: u32, address_to_write: *const ffi::c_void) -> Result<(), String> {
    unsafe {
        let data_ptr: *const i32 = &data_to_write;

        let handle = HandleWrapper::new(Threading::OpenProcess(Threading::PROCESS_ALL_ACCESS, Foundation::BOOL(0), pid).unwrap());
        let write_succeeded = Debug::WriteProcessMemory(handle.get_handle(), address_to_write, data_ptr.cast(), mem::size_of::<i32>(), ptr::null_mut());

        if !write_succeeded.as_bool() {
            print_error("WriteProcessMemory");
            return Err(String::from("WriteProcessMemory Error"));
        }
    }

    Ok(())
}