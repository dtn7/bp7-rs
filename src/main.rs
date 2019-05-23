use std::env;
use bp7::helpers::*;
use bp7::*;


fn usage(filepath : &String) {
    println!("usage {:?} <cmd> [args]", filepath);
    println!("\t decode <hexstring>");
    println!("\t rnd");

}

fn decode(bundle : &String) {
    let buf = unhexify(bundle).unwrap();
    //println!("decode: {:02x?}", &buf);
    let bndl : Bundle = buf.into();
    dbg!(&bndl);
}

fn main() {
    let args: Vec<String> = env::args().collect();


    if args.len() == 1 {
        usage(&args[0]);
        std::process::exit(1);
    }
    
    let cmd = &args[1];
    match cmd.as_str() {
        "rnd" => println!("{}\n", hexify(&rnd_bundle(bp7::CreationTimestamp::now()).to_cbor())),
        "decode" => {
            if args.len() == 3 {                        
                decode(&args[2]);
            } else {
                usage(&args[0]);
            }
        },            
        _ => usage(&args[0])
    }    
}