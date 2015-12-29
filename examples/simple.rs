
use std::env;
use std::path::PathBuf;

extern crate encryptfile;
use encryptfile as ef;

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

    let mut c = ef::Config::new();
    c.buffer_size(1048576*1)
        .password(ef::PasswordType::Text("swordfish".to_owned(),
            ef::default_scrypt_params()))
        .input_stream(ef::InputStream::File(in_file.to_owned()));

    match in_mode.as_ref() {
        "encrypt" => {
            let mut out_file = PathBuf::from(&in_file).file_name().unwrap().to_str().unwrap().to_owned();
            out_file.push_str(".enc");
            c.output_stream(ef::OutputStream::File(out_file.to_owned()));
            c.encrypt();
        },
        "decrypt" => {
            let out_file = PathBuf::from(&in_file).file_name().unwrap().to_str().unwrap().to_owned();
            let out_file = out_file.replace(".enc", "");
            c.output_stream(ef::OutputStream::File(out_file.to_owned()));
            c.decrypt();
        },
        _ => panic!("unsupported mode: {}", in_mode)
    }

    match ef::process(&c) {
        Err(e) => panic!("Error: {:?}", e),
        Ok(_) => println!("Done")
    }
}
