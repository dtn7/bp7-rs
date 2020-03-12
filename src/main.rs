use bp7::dtntime::DtnTimeHelpers;
use bp7::helpers::*;
use bp7::*;
use std::convert::TryInto;
use std::env;
use std::io;
use std::io::prelude::*;

fn usage(filepath: &str) {
    println!("usage {:?} <cmd> [args]", filepath);
    println!("\t decode <hexstring|stdin>");
    println!("\t dtntime [dtntimestamp] - prints current time as dtntimestamp or prints dtntime human readable");
    println!("\t d2u [dtntimestamp] - converts dtntime to unixstimestamp");
    println!("\t rnd - return a hexencoded random bundle");
}

fn decode(bundle: &str) {
    let buf = unhexify(bundle).unwrap();
    //println!("decode: {:02x?}", &buf);
    dbg!(serde_cbor::from_slice::<serde_cbor::Value>(&buf).unwrap());
    let bndl: Bundle = buf.try_into().expect("Error decoding bundle!");
    dbg!(&bndl);
}
fn decode_from_stdin() {
    let mut buf: Vec<u8> = Vec::new();
    io::stdin()
        .read_to_end(&mut buf)
        .expect("Error reading from stdin.");
    //println!("decode: {:02x?}", &buf);
    dbg!(serde_cbor::from_slice::<serde_cbor::Value>(&buf).unwrap());
    let bndl: Bundle = buf.try_into().expect("Error decoding bundle!");
    dbg!(&bndl);
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        usage(&args[0]);
        std::process::exit(1);
    }

    let cmd = &args[1];
    match cmd.as_str() {
        "rnd" => {
            let mut bndl = rnd_bundle(bp7::CreationTimestamp::now());
            println!("{}", bndl.id());
            println!("{}\n", hexify(&bndl.to_cbor()));
        }
        "decode" => {
            if args.len() == 3 {
                decode(&args[2]);
            } else {
                decode_from_stdin();
            }
        }
        "dtntime" => {
            if args.len() == 3 {
                let ts: bp7::dtntime::DtnTime = args[2].parse::<u64>().expect("invalid timestamp");
                println!("{}", ts.string());
            } else {
                println!("{}", bp7::dtn_time_now());
            }
        }
        "d2u" => {
            if args.len() == 3 {
                let ts: bp7::dtntime::DtnTime = args[2].parse::<u64>().expect("invalid timestamp");
                println!("{}", ts.unix());
            } else {
                usage(&args[0]);
            }
        }
        _ => usage(&args[0]),
    }
}
