#![allow(dead_code)]

mod config;

extern crate rand;
use self::rand::{Rng, OsRng, Isaac64Rng, SeedableRng, random};

extern crate crypto;
use self::crypto::scrypt::{scrypt, ScryptParams};

pub use config::{Config, PW_KEY_SIZE, IV_SIZE, PwKeyArray, IvArray, ScryptR, ScryptP, ScryptLogN};

use config::{PasswordType, PasswordKeyGenMethod, InitializationVector, RngMode};

struct EncryptState<'a> {
    config: &'a Config,
    pwkey: config::PwKeyArray,
    iv: config::IvArray,
}

#[derive(Debug)]
pub enum EncryptError {
    ValidateFailed(config::ValidateError),
    OsRngFailed(std::io::Error),
    PwKeyIsZeroed,
    IvIsZeroed,
    IvEqualsCheckValue,
    UnexpectedEnumVariant(String),
    InternalError,
}

pub fn make_scrypt_key(password: &str,
                       salt: &str,
                       logn: &ScryptLogN,
                       r: &ScryptR,
                       p: &ScryptP)
                       -> [u8; config::PW_KEY_SIZE] {
    let &ScryptLogN(logn) = logn;
    let &ScryptR(r) = r;
    let &ScryptP(p) = p;

    let salt = salt.as_bytes();
    let pw_bytes = password.as_bytes();

    let mut ek: [u8; PW_KEY_SIZE] = [0; PW_KEY_SIZE];

    let params = ScryptParams::new(logn, r, p);
    scrypt(pw_bytes, salt, &params, &mut ek);
    ek
}

pub fn generate_iv(c: &Config) -> Result<config::IvArray, EncryptError> {
    let init_val = 47;
    let mut iv: [u8; IV_SIZE] = [init_val; IV_SIZE];
    if let RngMode::Func(ref bf) = c.rng_mode {
        for i in 0..IV_SIZE {
            iv[i] = (*bf)();
        }
    } else {
        let mut os_rng = match OsRng::new() {
            Err(e) => return Err(EncryptError::OsRngFailed(e)),
            Ok(rng) => rng,
        };
        let seed = match c.rng_mode {
            RngMode::OsIssac => {
                [os_rng.next_u64(), os_rng.next_u64(), os_rng.next_u64(), os_rng.next_u64()]
            }
            RngMode::OsRandIssac => {
                // Use a combination of OsRng and and regular Rand in case OS has been backdoored
                [rand::random::<u64>(), rand::random::<u64>(), os_rng.next_u64(), os_rng.next_u64()]
            }
            RngMode::Func(_) => {
                return Err(EncryptError::UnexpectedEnumVariant("IV Func should have already been \
                                                                handled"
                                                                   .to_owned()))
            }
        };
        let mut issac_rng = Isaac64Rng::from_seed(&seed);

        // TODO: needs crypto review.
        // According to the rand crate docs, isaac64 is not supposed to be use for this.
        // But the Os RNG may be backdoored (*cough* Windows Dual_EC_DRBG).  So in the interests
        // of paranoia, use a mix of both.
        {
            let mut first = &mut iv[0..IV_SIZE / 2];
            os_rng.fill_bytes(first);
        }
        {
            let mut second = &mut iv[IV_SIZE / 2..IV_SIZE];
            issac_rng.fill_bytes(second);
        }
    }

    let check: [u8; IV_SIZE] = [init_val; IV_SIZE];
    if check == iv {
        return Err(EncryptError::IvEqualsCheckValue);
    }

    Ok(iv)
}

fn get_pw_key(c: &Config) -> Result<PwKeyArray, EncryptError> {
    match c.password {
        PasswordType::Unknown => {
            Err(EncryptError::UnexpectedEnumVariant("Password type unknown not allowed here"
                                                        .to_owned()))
        }
        PasswordType::Cleartext(ref pw, PasswordKeyGenMethod::Scrypt(ref logn, ref r, ref p)) => {
            Ok(make_scrypt_key(pw, &c.salt, logn, r, p))
        }
        PasswordType::Data(d) => Ok(d),
        PasswordType::Func(ref bf) => Ok((*bf)()),
    }
    .and_then(|pwkey| {
        if config::slice_is_zeroed(&pwkey) {
            // while its technically possible to have zeroed data at this point, its really
            // unlikely and probably indicates a bug.
            return Err(EncryptError::PwKeyIsZeroed);
        } else {
            Ok(pwkey)
        }
    })
}

fn get_iv(c: &Config) -> Result<IvArray, EncryptError> {
    match c.initialization_vector {
        InitializationVector::Unknown =>
            Err(EncryptError::UnexpectedEnumVariant("Unknown IV not allowed here".to_owned())),
        InitializationVector::Data(d) => Ok(d.clone()),
        InitializationVector::Func(ref bf) => Ok((*bf)()),
        InitializationVector::GenerateFromRng => generate_iv(c)
    }
    .and_then(|iv| {
        if config::slice_is_zeroed(&iv) {
            // while its technically possible to have zeroed data at this point, its really unlikely and
            // probably indicates a bug.
            return Err(EncryptError::IvIsZeroed);
        } else {
            Ok(iv)
        }
    })
}

pub fn encrypt(c: &Config) -> Result<(), EncryptError> {
    match c.validate() {
        Err(e) => return Err(EncryptError::ValidateFailed(e)),
        Ok(_) => (),
    };

    // obtain the password key
    let pwkey = try!(get_pw_key(c));
    // obtain the IV
    let iv = try!(get_iv(c));

    let state = EncryptState {
        config: c,
        pwkey: pwkey,
        iv: iv,
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use config::*;
    use std::env;

    fn check_eq(xs: &[u8], ys: &[u8], failmsg: String) {
        assert!(xs == ys, failmsg);
    }

    #[test]
    fn get_pwkey_scrypt() {
        let skip_long: i32 = env::var("SKIP_LONG").unwrap_or("0".to_owned()).parse().unwrap();

        let mut c = Config::new();
        c.input_stream(InputStream::Stdin);
        c.output_stream(OutputStream::Stdout);

        fn test_ct_combo(c: &mut Config,
                         logn: u8,
                         r: u32,
                         p: u32,
                         pw: &str,
                         salt: &str,
                         ex: PwKeyArray) {
            c.salt(salt.to_owned());
            c.password(PasswordType::Cleartext(pw.to_owned(),
                                               PasswordKeyGenMethod::Scrypt(ScryptLogN(logn),
                                                                            ScryptR(r),
                                                                            ScryptP(p))));
            let key = super::get_pw_key(&c);
            let key = key.map_err(|e| panic!("Unexpected error: {:?}", e));

            check_eq(&key.unwrap(),
                     &ex,
                     format!("pw key mismatch: pw: {}, salt: {}", pw, salt));
        }
        // this replicates the rust crypto tests just to make sure I didn't break it
        test_ct_combo(&mut c,
                      4,
                      1,
                      1,
                      "",
                      "",
                      [0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42,
                       0xc1, 0x8a, 0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
                       0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d,
                       0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
                       0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c,
                       0x38, 0xd1, 0x89, 0x06]);
        if skip_long == 0 {
            test_ct_combo(&mut c,
                          10,
                          8,
                          16,
                          "password",
                          "NaCl",
                          [0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7,
                           0x19, 0x0d, 0x01, 0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23,
                           0x78, 0x30, 0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62, 0x2e,
                           0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1, 0x09, 0x27,
                           0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee,
                           0x6d, 0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40]);
        }
    }

    #[test]
    fn get_pwkey_variants() {
        let mut c = Config::new();
        c.input_stream(InputStream::Stdin);
        c.output_stream(OutputStream::Stdout);

        let pwkey: PwKeyArray = [89; PW_KEY_SIZE];
        c.password(PasswordType::Data(pwkey));
        let key = super::get_pw_key(&c).unwrap();
        check_eq(&key, &pwkey, format!("Data pwkey variant failed"));

        let expected = pwkey;
        let pwfn = Box::new(move || pwkey);
        c.password(PasswordType::Func(pwfn));
        let key = super::get_pw_key(&c).unwrap();
        check_eq(&expected, &key, format!("Func pwkey variant failed"));

        let pwkey: PwKeyArray = [0; PW_KEY_SIZE];
        c.password(PasswordType::Data(pwkey));
        let key = super::get_pw_key(&c);
        let _ = key.map(|_| panic!("Expected error, but got valid key"));
    }

    #[test]
    fn get_iv_generate() {
        // test the various rnd modes.  since we can't really test that the output is
        // random, just make sure the functions return...something
        let mut c = Config::new();
        c.input_stream(InputStream::Stdin);
        c.output_stream(OutputStream::Stdout);

        c.initialization_vector(InitializationVector::GenerateFromRng);
        {
            let mut testmode = |rngmode| {
                c.rng_mode(rngmode);
                match super::get_iv(&c) {
                    Err(e) => panic!("Unexpected error generating iv: {:?}", e),
                    Ok(vec) => {
                        if slice_is_zeroed(&vec) {
                            panic!("got zeroed iv");
                        }
                    }
                };
            };

            testmode(RngMode::OsIssac);
            testmode(RngMode::OsRandIssac);
        }

        // test user-defined rng function
        let rngfn = Box::new(|| 6);
        c.rng_mode(RngMode::Func(rngfn));
        let expected: IvArray = [6; IV_SIZE];
        let geniv = super::get_iv(&c).unwrap();
        check_eq(&expected, &geniv, format!("Data iv variant failed"));
    }

    #[test]
    fn get_iv_variants() {
        let mut c = Config::new();
        c.input_stream(InputStream::Stdin);
        c.output_stream(OutputStream::Stdout);

        let iv: IvArray = [89; IV_SIZE];
        c.initialization_vector(InitializationVector::Data(iv));
        let geniv = super::get_iv(&c).unwrap();
        check_eq(&iv, &geniv, format!("Data iv variant failed"));

        let expected = iv;
        let ivfn = Box::new(move || iv);
        c.initialization_vector(InitializationVector::Func(ivfn));
        let geniv = super::get_iv(&c).unwrap();
        check_eq(&geniv, &expected, format!("Func iv variant failed"));

        let iv: IvArray = [0; IV_SIZE];
        c.initialization_vector(InitializationVector::Data(iv));
        let geniv = super::get_iv(&c);
        let _ = geniv.map(|_| panic!("Expected error, but got valid iv"));
    }
}
