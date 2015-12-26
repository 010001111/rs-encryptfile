use std::iter::repeat;

extern crate crypto;
use self::crypto::{ symmetriccipher, buffer, aes, blockmodes };
use self::crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use self::crypto::sha2::Sha256;
use self::crypto::hmac::Hmac;
use self::crypto::mac::Mac;

pub struct CryptoHelper {
    encryptor: Box<crypto::symmetriccipher::Encryptor>,
    got_eof_on_encrypt: bool,
    pub encrypt_hmac: Hmac<Sha256>,

    decryptor: Box<crypto::symmetriccipher::Decryptor>,
    got_eof_on_decrypt: bool,
    pub decrypt_hmac: Hmac<Sha256>,
}

pub fn hmac_to_vec(hmac: &mut Hmac<Sha256>) -> Vec<u8> {
    let mut hmac_raw: Vec<u8> = repeat(0).take(hmac.output_bytes()).collect();
    hmac.raw_result(&mut hmac_raw);
    hmac_raw
}

impl CryptoHelper {
    pub fn new(key:&[u8], iv:&[u8]) -> Self {
        let encryptor = aes::cbc_encryptor(
                aes::KeySize::KeySize256,
                key,
                iv,
                blockmodes::PkcsPadding);
        let decryptor = aes::cbc_decryptor(
                aes::KeySize::KeySize256,
                key,
                iv,
                blockmodes::PkcsPadding);
        CryptoHelper {
            encryptor: encryptor,
            decryptor: decryptor,
            got_eof_on_encrypt: false,
            got_eof_on_decrypt: false,
            encrypt_hmac: Hmac::new(Sha256::new(), &key),
            decrypt_hmac: Hmac::new(Sha256::new(), &key),
        }
    }

    pub fn encrypt(&mut self, data: &[u8], is_all_data:bool) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
        if self.got_eof_on_encrypt {
            panic!("Already received encryption eof, can't encrypt anymore; reinit crypto helper"); // TODO: remove this panic
        }
        if is_all_data {
            self.got_eof_on_encrypt = true;
        }

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(data);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = try!(self.encryptor.encrypt(&mut read_buffer, &mut write_buffer, is_all_data));

            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }

        self.encrypt_hmac.input(&final_result);

        Ok(final_result)
    }

    pub fn decrypt(&mut self, encrypted_data: &[u8], is_all_data:bool) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
        if self.got_eof_on_decrypt {
            panic!("Already received decryption eof, can't decrypt anymore; reinit crypto helper"); // TODO: remove this panic
        }
        if is_all_data {
            self.got_eof_on_decrypt = true;
        }

        self.decrypt_hmac.input(encrypted_data);

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = try!(self.decryptor.decrypt(&mut read_buffer, &mut write_buffer, is_all_data));
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }

        Ok(final_result)
    }
}
