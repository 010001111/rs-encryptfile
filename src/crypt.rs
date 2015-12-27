use std::io::{Read, Write, Seek, SeekFrom};
use std::path::PathBuf;
use std::fs::remove_file;
use std::mem;

extern crate crypto;
use self::crypto::mac::{Mac, MacResult};

extern crate byteorder;
use self::byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};

pub use super::EncryptError;
pub use super::process;
use config::*;

use config;
use crypto_util;

const MAGIC: u64 = 0xDEADBEEEEEEFCAFE;
const FORMAT_VERSION: u32 = 1;

pub struct EncryptState<'a> {
    pub config: &'a Config,
    pub pwkey: config::PwKeyArray,
    pub iv: config::IvArray,
    pub read_buf: &'a mut [u8],
    pub write_buf: &'a mut [u8],
}

pub struct TempFileRemover {
    pub filename: String,
}

impl Drop for TempFileRemover {
    fn drop(&mut self) {
        let pb = PathBuf::from(&self.filename);
        if pb.is_file() {
            match remove_file(&self.filename) {
                Err(e) => println!("Failed to remove temporary file: {}: {}", &self.filename, e),
                Ok(_) => (),
            }
        }
    }
}

struct FileHeader {
    magic: u64,
    fversion: u32,
    iv: IvArray,
    hmac_len: u32,
}

const HEADER_RESERVED: usize = 40; // reserved space after FileHeader

impl FileHeader {
    pub fn write(&self, s: &mut Write) -> Result<(), EncryptError> {
        try!(s.write_u64::<LittleEndian>(self.magic));
        try!(s.write_u32::<LittleEndian>(self.fversion));
        try!(s.write_u32::<LittleEndian>(self.hmac_len));
        try!(s.write_all(&self.iv));
        Ok(())
    }

    pub fn verify(&self) -> Result<(), EncryptError> {
        if self.magic != MAGIC {
            return Err(EncryptError::BadHeaderMagic);
        }
        if self.fversion != FORMAT_VERSION {
            return Err(EncryptError::UnexpectedVersion(self.fversion, FORMAT_VERSION));
        }
        if self.hmac_len == 0 {
            return Err(EncryptError::InvalidHmacLength);
        }
        if config::slice_is_zeroed(&self.iv) {
            return Err(EncryptError::IvIsZeroed);
        }
        Ok(())
    }

    pub fn read(s: &mut Read) -> Result<FileHeader, EncryptError> {
        let mut header = FileHeader {
            magic: try!(s.read_u64::<LittleEndian>()),
            fversion: try!(s.read_u32::<LittleEndian>()),
            hmac_len: try!(s.read_u32::<LittleEndian>()),
            iv: [0; IV_SIZE],
        };

        // TODO: use read_exact when it is stable
        let nread = try!(s.read(&mut header.iv));
        if nread != IV_SIZE {
            return Err(EncryptError::ShortIvRead);
        }

        try!(header.verify());

        Ok(header)
    }
}

pub fn encrypt(state: EncryptState,
               mut in_stream: Box<SeekRead>,
               mut out_stream: Box<SeekWrite>)
               -> Result<(), EncryptError> {
    let mut crypto = crypto_util::CryptoHelper::new(&state.pwkey, &state.iv, true);
    let mut buf = state.read_buf;

    // reserve space for header + hmac
    let header_size = mem::size_of::<FileHeader>();
    let header_capacity = header_size + HEADER_RESERVED;
    let header: Vec<u8> = vec![0;header_capacity];
    try!(out_stream.write_all(&header));

    loop {
        let num_read = try!(in_stream.read(buf));
        let enc_bytes = &buf[0..num_read];
        let eof = num_read == 0;
        let res = crypto.encrypt(enc_bytes, eof);
        match res {
            Err(e) => return Err(EncryptError::CryptoError(e)),
            Ok(d) => try!(out_stream.write_all(&d)),
        }
        if eof {
            break;
        }
    }

    let hmac = crypto_util::hmac_to_vec(&mut crypto.hmac);
    if hmac.len() + header_size >= header_capacity {
        return Err(EncryptError::HeaderTooSmall);
    }
    let header = FileHeader {
        magic: MAGIC,
        fversion: FORMAT_VERSION,
        iv: state.iv.clone(),
        hmac_len: hmac.len() as u32,
    };
    try!(out_stream.seek(SeekFrom::Start(0)));
    try!(header.write(&mut out_stream));
    // hmac goes after the header
    try!(out_stream.write_all(&hmac));

    Ok(())
}

pub fn decrypt(state: EncryptState,
               mut in_stream: Box<SeekRead>,
               mut out_stream: Box<SeekWrite>)
               -> Result<(), EncryptError> {
    let mut buf = state.read_buf;
    let header = try!(FileHeader::read(&mut in_stream));

    // TODO: use read_exact when it is stable
    let hmac_len = header.hmac_len as usize;
    let mut hmac_bytes: Vec<u8> = vec![0;hmac_len];
    let nread = try!(in_stream.read(&mut hmac_bytes));
    if nread != hmac_len {
        return Err(EncryptError::ShortHmacRead);
    }
    let mut crypto = crypto_util::CryptoHelper::new(&state.pwkey, &header.iv, false);
    // seek to data pos
    let header_size = mem::size_of::<FileHeader>();
    let header_capacity = header_size + HEADER_RESERVED;
    try!(in_stream.seek(SeekFrom::Start(header_capacity as u64)));

    loop {
        let num_read = try!(in_stream.read(buf));
        let enc_bytes = &buf[0..num_read];
        let eof = num_read == 0;
        let res = crypto.decrypt(enc_bytes, eof);
        match res {
            Err(e) => return Err(EncryptError::CryptoError(e)),
            Ok(d) => try!(out_stream.write_all(&d)),
        }
        if eof {
            break;
        }
    }

    let mut computed_hmac = crypto.hmac;
    let expected_hmac = MacResult::new(&hmac_bytes);
    if computed_hmac.result() != expected_hmac {
        return Err(EncryptError::HmacMismatch);
    }

    Ok(())
}

// ===============================================================================================
#[cfg(test)]
mod tests {
    // extern crate tempfile;
    // use self::tempfile::TempFile;
    use std::fs::{remove_file, File, OpenOptions};
    use std::io::{Read, Write, Seek, SeekFrom};

    extern crate tempdir;
    use self::tempdir::TempDir;

    use super::EncryptError;
    use super::FileHeader;

    use config::*;

    fn write_test_file(dir: &TempDir, name: &str, contents: &str) -> String {
        let tdp = dir.path().to_path_buf();
        let mut fname = tdp.clone();
        fname.push(name);
        let fname = fname.to_str().unwrap();
        let mut fstream = File::create(&fname).unwrap();
        let _ = write!(fstream, "{}", contents);
        fname.to_owned()
    }

    fn encrypt_file(td: &TempDir,
                    in_name: &str,
                    out_name: &str,
                    pw: &str,
                    contents: &str)
                    -> (Result<(), EncryptError>, String, String) {
        let in_fname = write_test_file(&td, in_name, contents);
        let out_fname = write_test_file(&td, out_name, "");
        remove_file(&out_fname).unwrap();

        let mut c = Config::new();
        c.input_stream(InputStream::File(in_fname.to_owned()));
        c.output_stream(OutputStream::File(out_fname.to_owned(), FileOptions::None));
        c.initialization_vector(InitializationVector::GenerateFromRng);
        c.password(PasswordType::Text(pw.to_owned(), default_scrypt_params()));
        c.encrypt();

        let res = super::process(&c).map_err(|e| panic!("error encrypting: {:?}", e));

        (res, in_fname, out_fname)
    }

    #[test]
    fn crypt_basic() {
        let td = TempDir::new("crypt_basic").unwrap();

        let expected = "Hello World!";

        let (res, _, out_fname) = encrypt_file(&td, "in_file", "out_file", "Swordfish", expected);
        let _ = res.map_err(|e| panic!("error encrypting: {:?}", e));

        let in_fname = out_fname;
        let out_fname = write_test_file(&td, "out_file.dec", "");
        remove_file(&out_fname).unwrap();

        let mut c = Config::new();
        c.password(PasswordType::Text("Swordfish".to_owned(), default_scrypt_params()));
        c.input_stream(InputStream::File(in_fname.to_owned()));
        c.output_stream(OutputStream::File(out_fname.to_owned(), FileOptions::None));
        c.decrypt();

        let _ = super::process(&c).map_err(|e| panic!("error decrypting: {:?}", e));

        let mut fout_stream = File::open(out_fname).unwrap();
        let mut s = String::new();
        fout_stream.read_to_string(&mut s).unwrap();
        assert!(s == expected,
                format!("Expected '{}', got '{}'", expected, s));
    }

    #[test]
    fn crypt_wrong_pw() {
        let td = TempDir::new("crypt_wrong_pw").unwrap();
        let (res, _, out_fname) = encrypt_file(&td, "in_file", "out_file", "Swordfish", "stuff");
        let _ = res.map_err(|e| panic!("error encrypting: {:?}", e));

        let in_fname = out_fname;
        let out_fname = write_test_file(&td, "out_file.dec", "");
        remove_file(&out_fname).unwrap();

        let mut c = Config::new();
        c.password(PasswordType::Text("Clownfish".to_owned(), default_scrypt_params()));
        c.input_stream(InputStream::File(in_fname.to_owned()));
        c.output_stream(OutputStream::File(out_fname.to_owned(), FileOptions::None));
        c.decrypt();
        match super::process(&c) {
            Err(EncryptError::CryptoError(_)) => (),
            x => panic!("Unexpected result: {:?}", x),
        }
    }

    #[test]
    fn crypt_change_iv() {
        let td = TempDir::new("crypt_change_iv").unwrap();
        let (res, _, out_fname) = encrypt_file(&td, "in_file", "out_file", "Swordfish", "stuff");
        let _ = res.map_err(|e| panic!("error encrypting: {:?}", e));

        let mut fout_stream = OpenOptions::new().read(true).write(true).open(&out_fname).unwrap();
        let mut header = FileHeader::read(&mut fout_stream).unwrap();
        header.iv = [6; IV_SIZE];
        fout_stream.seek(SeekFrom::Start(0)).unwrap();
        header.write(&mut fout_stream).unwrap();
        drop(fout_stream);

        let in_fname = out_fname;
        let out_fname = write_test_file(&td, "out_file.dec", "");
        remove_file(&out_fname).unwrap();

        let mut c = Config::new();
        c.password(PasswordType::Text("Swordfish".to_owned(), default_scrypt_params()));
        c.input_stream(InputStream::File(in_fname.to_owned()));
        c.output_stream(OutputStream::File(out_fname.to_owned(), FileOptions::None));
        c.decrypt();
        match super::process(&c) {
            Err(EncryptError::CryptoError(_)) => (),
            x => panic!("Unexpected result: {:?}", x),
        }
    }

    #[test]
    fn crypt_change_hmac() {
        let td = TempDir::new("crypt_change_hmac").unwrap();
        let (res, _, out_fname) = encrypt_file(&td, "in_file", "out_file", "Swordfish", "stuff");
        let _ = res.map_err(|e| panic!("error encrypting: {:?}", e));

        let mut fout_stream = OpenOptions::new().read(true).write(true).open(&out_fname).unwrap();
        let _ = FileHeader::read(&mut fout_stream).unwrap();
        write!(fout_stream, "badhmac").unwrap();
        drop(fout_stream);

        let in_fname = out_fname;
        let out_fname = write_test_file(&td, "out_file.dec", "");
        remove_file(&out_fname).unwrap();

        let mut c = Config::new();
        c.password(PasswordType::Text("Swordfish".to_owned(), default_scrypt_params()));
        c.input_stream(InputStream::File(in_fname.to_owned()));
        c.output_stream(OutputStream::File(out_fname.to_owned(),FileOptions::None));
        c.decrypt();
        match super::process(&c) {
            Err(EncryptError::HmacMismatch) => (),
            x => panic!("Unexpected result: {:?}", x),
        }
    }

    #[test]
    fn crypt_change_data() {
        let td = TempDir::new("crypt_change_data").unwrap();
        let (res, _, out_fname) = encrypt_file(&td, "in_file", "out_file", "Swordfish", "stuff");
        let _ = res.map_err(|e| panic!("error encrypting: {:?}", e));

        let mut fout_stream = OpenOptions::new().read(true).write(true).open(&out_fname).unwrap();
        fout_stream.seek(SeekFrom::End(-2)).unwrap();
        let z: [u8; 2] = [50; 2];
        fout_stream.write(&z).unwrap();
        drop(fout_stream);

        let in_fname = out_fname;
        let out_fname = write_test_file(&td, "out_file.dec", "");
        remove_file(&out_fname).unwrap();

        let mut c = Config::new();
        c.password(PasswordType::Text("Swordfish".to_owned(), default_scrypt_params()));
        c.input_stream(InputStream::File(in_fname.to_owned()));
        c.output_stream(OutputStream::File(out_fname.to_owned(),FileOptions::None));
        c.decrypt();
        match super::process(&c) {
            Err(EncryptError::CryptoError(_)) => (),
            x => panic!("Unexpected result: {:?}", x),
        }
    }

    #[test]
    fn crypt_overwrite() {
        let td = TempDir::new("crypt_overwrite").unwrap();

        let in_fname = write_test_file(&td, "in_name", "");
        let out_fname = write_test_file(&td, "out_name", "");

        let mut c = Config::new();
        c.input_stream(InputStream::File(in_fname.to_owned()));
        c.output_stream(OutputStream::File(out_fname.to_owned(), FileOptions::None));
        c.initialization_vector(InitializationVector::GenerateFromRng);
        c.password(PasswordType::Text("Booger".to_owned(), default_scrypt_params()));
        c.encrypt();

        match super::process(&c) {
            Err(EncryptError::OutputFileExists) => (),
            x => panic!("Unexpected result: {:?}", x),
        }

        c.output_stream(OutputStream::File(out_fname.to_owned(), FileOptions::AllowOverwrite));
        match super::process(&c) {
            Ok(_) => (),
            x => panic!("Unexpected result: {:?}", x),
        }
    }
}
