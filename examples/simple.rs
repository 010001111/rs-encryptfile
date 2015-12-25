use std::fs::File;
use std::env;
use std::path::PathBuf;

extern crate encryptfile;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <encrypt|decrypt> filename", args[0]);
        return;
    }
    let in_mode = args[1].to_owned();
    let in_file = args[2].to_owned();

    match PathBuf::from(&in_file).metadata() {
        Err(e) => panic!("Error reading file: {}", e),
        Ok(md) => println!("Input file size is: {}", md.len())
    }
    println!("Mode: {}", &in_mode);

    let mut c = encryptfile::Config::new();
    c.buffer_size(1048576*1)
        .password(encryptfile::PasswordType::Cleartext("swordfish".to_owned(),
            encryptfile::default_scrypt_params()))
        .input_stream(encryptfile::InputStream::File(in_file.to_owned()));

    match in_mode.as_ref() {
        "encrypt" => {
            let mut out_file = PathBuf::from(&in_file).file_name().unwrap().to_str().unwrap().to_owned();
            out_file.push_str(".enc");
            c.output_stream(encryptfile::OutputStream::File(out_file.to_owned()));
            c.encrypt();
        },
        "decrypt" => {
            let mut out_file = PathBuf::from(&in_file).file_name().unwrap().to_str().unwrap().to_owned();
            let mut out_file = out_file.replace(".enc", "");
            c.output_stream(encryptfile::OutputStream::File(out_file.to_owned()));
            c.decrypt();
        },
        _ => panic!("unsupported mode: {}", in_mode)
    }

    match encryptfile::process(&c) {
        Err(e) => panic!("Error: {:?}", e),
        Ok(_) => println!("Done")
    }
}
