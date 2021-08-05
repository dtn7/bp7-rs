use bp7::{crc, helpers::*};

#[cfg(target_arch = "wasm32")]
use stdweb::*;

#[cfg(target_arch = "wasm32")]
macro_rules! print {
    ($($tt:tt)*) => {{
        let msg = format!($($tt)*);
        js! {
            if(!window.tbuf) window.tbuf = "";
            window.tbuf += @{msg};
        }
    }}
}

#[cfg(target_arch = "wasm32")]
macro_rules! println {
    ($($tt:tt)*) => {{
        let msg = format!($($tt)*);
        js! {
            if(!window.tbuf) window.tbuf = "";
            console.log(window.tbuf + @{ msg });
            window.tbuf = "";
        }
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
