//use std::env;
use core::ffi;
use memory_hacking;

// fn validate_args(args: &Vec<String>) -> Result<String, String> {
//     Ok(String::from("sds"))
// }

fn main() {
   // let args = env::args().collect();
   // validate_args(&args);
    let process_name = "asm-testing.exe";

    let pid = memory_hacking::get_process_id(&process_name);
    if let Some(pid) = pid {
        let address = 0xb2d12ff38c as *const ffi::c_void;
        let data = memory_hacking::read_process_memory::<i32>(pid, address);

        println!("{}", data);

        let r = memory_hacking::write_process_memory(9876, pid, address);
        if let Err(e) = r {
            println!("Writing memory failed with the error: {}", e);
        }
    } else {
        println!("'{}' does not exist", process_name);
    }
}