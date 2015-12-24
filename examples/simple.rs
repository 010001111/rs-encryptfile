use std::fs::File;
use std::env;
use std::path::PathBuf;

extern crate encryptfile;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("Writes encrypted bytes of specified file to './filename.enc'\nUsage: {} filename_to_encrypt", args[0]);
        return;
    }
    let in_file = args[1].to_owned();

    match PathBuf::from(&in_file).metadata() {
        Err(e) => panic!("Error reading file: {}", e),
        Ok(md) => println!("Input file size is: {}", md.len())
    }

    let mut out_file = PathBuf::from(&in_file).file_name().unwrap().to_str().unwrap().to_owned();
    out_file.push_str(".enc");

    let mut c = encryptfile::Config::new();
    c.encrypt()
        .buffer_size(1048576*1)
        .password(encryptfile::PasswordType::Cleartext("swordfish".to_owned(),
            encryptfile::default_scrypt_params()))
        .input_stream(encryptfile::InputStream::File(in_file))
        .output_stream(encryptfile::OutputStream::File(out_file.to_owned()));
    match encryptfile::process(&c) {
        Err(e) => panic!("Error: {:?}", e),
        Ok(_) => println!("Wrote {}",&out_file)
    }
}
