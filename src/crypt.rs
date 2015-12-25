use std::io::{Read,Write,Seek,SeekFrom};
use std::path::PathBuf;
use std::fs::{remove_file};
use std::mem;

extern crate crypto;
use self::crypto::mac::{Mac,MacResult};

extern crate byteorder;
use self::byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};

use super::*;

use config;
use crypto_util;

const MAGIC:u64 = 0xDEADBEEEEEEFCAFE;
const FORMAT_VERSION:u32 = 1;

pub struct EncryptState<'a> {
    pub config: &'a Config,
    pub pwkey: config::PwKeyArray,
    pub iv: config::IvArray,
    pub read_buf: &'a mut [u8],
    pub write_buf: &'a mut [u8]
}

pub struct TempFileRemover {
    pub filename: String
}

impl Drop for TempFileRemover {
    fn drop(&mut self) {
        let pb = PathBuf::from(&self.filename);
        if pb.is_file() {
            match remove_file(&self.filename) {
                Err(e) => println!("Failed to remove temporary file: {}: {}", &self.filename, e),
                Ok(_) => ()
            }
        }
    }
}

struct FileHeader {
    magic:u64,
    fversion:u32,
    iv:IvArray,
    hmac_len:u32
}

const HEADER_RESERVED:usize = 40; // reserved space after FileHeader

impl FileHeader {
    pub fn write(&self, s:&mut Write) -> Result<(),EncryptError> {
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
            return Err(EncryptError::UnexpectedVersion(self.fversion,FORMAT_VERSION));
        }
        if self.hmac_len == 0 {
            return Err(EncryptError::InvalidHmacLength);
        }
        if config::slice_is_zeroed(&self.iv) {
            return Err(EncryptError::IvIsZeroed);
        }
        Ok(())
    }

    pub fn read(s:&mut Read) -> Result<FileHeader, EncryptError> {
        let mut header = FileHeader {
            magic: try!(s.read_u64::<LittleEndian>()),
            fversion: try!(s.read_u32::<LittleEndian>()),
            hmac_len: try!(s.read_u32::<LittleEndian>()),
            iv: [0;IV_SIZE],
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

pub fn encrypt(state:EncryptState, mut in_stream:Box<SeekRead>, mut out_stream:Box<SeekWrite>) -> Result<(), EncryptError> {
    let mut crypto = crypto_util::CryptoHelper::new(&state.pwkey,&state.iv);
    let mut buf = state.read_buf;

    // reserve space for header + hmac
    let header_size = mem::size_of::<FileHeader>();
    let header_capacity = header_size + HEADER_RESERVED;
    let header:Vec<u8> = vec![0;header_capacity];
    try!(out_stream.write_all(&header));

    loop {
        let num_read = try!(in_stream.read(buf));
        let enc_bytes = &buf[0 .. num_read];
        let eof = num_read == 0;
        let res = crypto.encrypt(enc_bytes, eof);
        match res {
            Err(e) => return Err(EncryptError::CryptoError(e)),
            Ok(d) => try!(out_stream.write_all(&d))
        }
        if eof {
            break;
        }
    }

    let hmac = crypto_util::hmac_to_vec(&mut crypto.encrypt_hmac);
    if hmac.len() + header_size >= header_capacity {
        return Err(EncryptError::HeaderTooSmall)
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

pub fn decrypt(state:EncryptState, mut in_stream:Box<SeekRead>, mut out_stream:Box<SeekWrite>) -> Result<(), EncryptError> {
    let mut buf = state.read_buf;
    let header = try!(FileHeader::read(&mut in_stream));

    // TODO: use read_exact when stable
    let hmac_len = header.hmac_len as usize;
    let mut hmac_bytes:Vec<u8> = vec![0;hmac_len];
    let nread = try!(in_stream.read(&mut hmac_bytes));
    if nread != hmac_len {
        return Err(EncryptError::ShortHmacRead);
    }
    let mut crypto = crypto_util::CryptoHelper::new(&state.pwkey,&header.iv);
    // seek to data pos
    let header_size = mem::size_of::<FileHeader>();
    let header_capacity = header_size + HEADER_RESERVED;
    try!(in_stream.seek(SeekFrom::Start(header_capacity as u64)));

    loop {
        let num_read = try!(in_stream.read(buf));
        let enc_bytes = &buf[0 .. num_read];
        let eof = num_read == 0;
        let res = crypto.decrypt(enc_bytes, eof);
        match res {
            Err(e) => return Err(EncryptError::CryptoError(e)),
            Ok(d) => try!(out_stream.write_all(&d))
        }
        if eof {
            break;
        }
    }

    let mut computed_hmac = crypto.decrypt_hmac;
    let expected_hmac = MacResult::new(&hmac_bytes);
    if computed_hmac.result() != expected_hmac {
        return Err(EncryptError::HmacMismatch)
    }

    Ok(())
}
