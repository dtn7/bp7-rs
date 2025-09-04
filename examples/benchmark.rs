use bp7::{crc, helpers::*};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use web_sys::console;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
thread_local! {
    static PRINT_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::new());
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
macro_rules! print {
    ($($tt:tt)*) => {{
        let msg = format!($($tt)*);
        PRINT_BUFFER.with(|buffer| {
            buffer.borrow_mut().push_str(&msg);
        });
    }}
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
macro_rules! println {
    ($($tt:tt)*) => {{
        let msg = format!($($tt)*);
        PRINT_BUFFER.with(|buffer| {
            let mut buf = buffer.borrow_mut();
            buf.push_str(&msg);
            console::log_1(&wasm_bindgen::JsValue::from_str(&buf));
            buf.clear();
        });
    }}
}

const RUNS: i64 = 100_000;

fn main() {
    let crcno = bench_bundle_create(RUNS, crc::CRC_NO);
    let crc16 = bench_bundle_create(RUNS, crc::CRC_16);
    let crc32 = bench_bundle_create(RUNS, crc::CRC_32);

    //print!("{:x?}", crcno[0]);
    //println!("{}", bp7::hexify(&crcno[0]));

    bench_bundle_encode(RUNS, crc::CRC_NO);
    bench_bundle_encode(RUNS, crc::CRC_16);
    bench_bundle_encode(RUNS, crc::CRC_32);

    bench_bundle_load(RUNS, crc::CRC_NO, crcno);
    bench_bundle_load(RUNS, crc::CRC_16, crc16);
    bench_bundle_load(RUNS, crc::CRC_32, crc32);

    //dbg!(crcno[0].len());
    //dbg!(crc16[0].len());
    //dbg!(crc32[0].len());
}
