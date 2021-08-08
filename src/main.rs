use bp7::dtntime::DtnTimeHelpers;
use bp7::helpers::*;
use bp7::primary::PrimaryBlock;
use bp7::*;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::io;
use std::io::prelude::*;

fn usage(filepath: &str) {
    println!("usage {:?} <cmd> [args]", filepath);
    println!("\t encode <manifest> <payloadfile | - > [-x] - encode bundle and output raw bytes or hex string (-x)");
    println!("\t decode <hexstring | - > [-p] - decode bundle or payload only (-p)");
    println!("\t dtntime [dtntimestamp] - prints current time as dtntimestamp or prints dtntime human readable");
    println!("\t d2u [dtntimestamp] - converts dtntime to unixstimestamp");
    println!("\t rnd [-r] - return a random bundle either hexencoded or raw bytes (-r)");
    println!("\t benchmark - run a simple benchmark encoding/decoding bundles");
}

fn manifest_to_primary(manifest: &str) -> PrimaryBlock {
    let manifest = fs::read(manifest).expect("error reading bundle manifest");
    let mut primary = bp7::primary::PrimaryBlockBuilder::default()
        .crc(bp7::crc::CrcValue::CrcNo)
        .creation_timestamp(bp7::CreationTimestamp::now())
        .lifetime("1d".parse::<humantime::Duration>().unwrap().into());

    for line in String::from_utf8_lossy(&manifest)
        .split('\n')
        .map(|f| f.trim())
        .filter(|l| !l.is_empty() || l.starts_with("^#"))
        .filter(|l| l.contains('='))
    {
        let result: Vec<&str> = line.splitn(2, '=').map(|f| f.trim()).collect();
        match result[0] {
            "destination" => {
                primary = primary.destination(result[1].try_into().unwrap());
            }
            "source" => {
                primary = primary.source(result[1].try_into().unwrap());
            }
            "report_to" => {
                primary = primary.report_to(result[1].try_into().unwrap());
            }
            "lifetime" => {
                primary =
                    primary.lifetime(result[1].parse::<humantime::Duration>().unwrap().into());
            }
            "flags" => {
                primary = primary.bundle_control_flags(result[1].parse().unwrap());
            }
            _ => {
                eprintln!("unknown key: {}", result[0]);
            }
        }
    }
    primary.build().expect("error building primary block")
}
fn generate_bundle(primary_block: PrimaryBlock, payload: Vec<u8>, hex: bool) {
    let payload_block = bp7::new_payload_block(0, payload);

    let mut b = bundle::Bundle::new(primary_block, vec![payload_block]);

    b.set_crc(bp7::crc::CRC_NO);
    b.validate().expect("created in invalid bundle");
    let cbor = b.to_cbor();

    if hex {
        println!("{}", bp7::helpers::hexify(&cbor));
    } else {
        std::io::stdout().write_all(&cbor).unwrap();
    }
}

fn encode(manifest: &str, data: &str, hex: bool) {
    let primary_block = manifest_to_primary(manifest);

    let payload = fs::read(data).expect("error reading bundle payload");
    generate_bundle(primary_block, payload, hex);
}

fn encode_from_stdin(manifest: &str, hex: bool) {
    let primary_block = manifest_to_primary(manifest);
    let mut payload: Vec<u8> = Vec::new();
    io::stdin()
        .read_to_end(&mut payload)
        .expect("Error reading from stdin.");
    generate_bundle(primary_block, payload, hex);
}

fn decode(bundle: &str, payload_only: bool) {
    let buf = unhexify(bundle).unwrap();
    //println!("decode: {:02x?}", &buf);
    let bndl: Bundle = buf.try_into().expect("Error decoding bundle!");
    if payload_only {
        if bndl.payload().is_some() {
            std::io::stdout()
                .write_all(bndl.payload().unwrap())
                .unwrap();
        }
    } else {
        dbg!(&bndl);
    }
}
fn decode_from_stdin(payload_only: bool) {
    let mut buf: Vec<u8> = Vec::new();
    io::stdin()
        .read_to_end(&mut buf)
        .expect("Error reading from stdin.");
    //println!("decode: {:02x?}", &buf);
    //serde_cbor::from_slice::<serde_cbor::Value>(&buf).unwrap();
    let bndl: Bundle = buf.try_into().expect("Error decoding bundle!");
    if payload_only {
        if bndl.payload().is_some() {
            std::io::stdout()
                .write_all(bndl.payload().unwrap())
                .expect("error writing to stdout");
        }
    } else {
        dbg!(&bndl);
    }
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
            eprintln!("{}", bndl.id());
            if args.len() == 3 && args[2] == "-r" {
                std::io::stdout()
                    .write_all(&bndl.to_cbor())
                    .expect("unable to write to stdout");
            } else {
                println!("{}\n", hexify(&bndl.to_cbor()));
            }
        }
        "encode" => {
            let hex = if args.len() == 4 {
                false
            } else if args.len() == 5 {
                args[4] == "-x"
            } else {
                usage(&args[0]);
                std::process::exit(1);
            };
            if args[3] == "-" {
                encode_from_stdin(&args[2], hex);
            } else {
                encode(&args[2], &args[3], hex);
            }
        }
        "decode" => {
            let payload_only = if args.len() == 3 {
                false
            } else if args.len() == 4 {
                args[3] == "-p"
            } else {
                usage(&args[0]);
                std::process::exit(1);
            };
            if args[2] == "-" {
                decode_from_stdin(payload_only);
            } else {
                decode(&args[2], payload_only);
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
        "benchmark" => {
            let runs = 100_000;
            let crcno = bench_bundle_create(runs, crc::CRC_NO);
            let crc16 = bench_bundle_create(runs, crc::CRC_16);
            let crc32 = bench_bundle_create(runs, crc::CRC_32);

            //print!("{:x?}", crcno[0]);
            //println!("{}", bp7::hexify(&crcno[0]));

            bench_bundle_encode(runs, crc::CRC_NO);
            bench_bundle_encode(runs, crc::CRC_16);
            bench_bundle_encode(runs, crc::CRC_32);

            bench_bundle_load(runs, crc::CRC_NO, crcno);
            bench_bundle_load(runs, crc::CRC_16, crc16);
            bench_bundle_load(runs, crc::CRC_32, crc32);

            //dbg!(crcno[0].len());
            //dbg!(crc16[0].len());
            //dbg!(crc32[0].len());
        }
        _ => usage(&args[0]),
    }
}
