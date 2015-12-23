pub const PW_KEY_SIZE: usize = 64;
pub const IV_SIZE: usize = 16;

use std::io::{Read,Write};

pub type PwKeyArray = [u8; PW_KEY_SIZE];

pub type IvArray = [u8; IV_SIZE];

pub enum InputStream {
    Unknown,
    Stdin,
    File(String),
    Reader(Box<Read>)
}

pub enum OutputStream {
    Unknown,
    Stdout,
    File(String),
    Writer(Box<Write>)
}

pub enum OutputFormat {
    //EncryptedZip,
    EncryptFile,
}

pub enum RngMode {
    OsIssac,
    OsRandIssac,
    Func(Box<Fn() -> u8>)
}

pub enum InitializationVector {
    Unknown,
    GenerateFromRng,
    Data(IvArray),
    Func(Box<Fn() -> IvArray>)
}

pub enum EncryptionMethod {
    AesCbc256
}

pub enum LineEndingOnEncrypt {
    Ignore,
    ConvertToNewline,
}

pub enum LineEndingOnDecrypt {
    Ignore,
    ConvertToOs
}

pub struct ScryptLogN(pub u8);
pub struct ScryptR(pub u32);
pub struct ScryptP(pub u32);
pub enum PasswordKeyGenMethod {
    Scrypt(ScryptLogN,ScryptR,ScryptP)
}

pub enum PasswordType {
    Unknown,
    Cleartext(String,PasswordKeyGenMethod), // Note: leading/trailing whitespace is not trimmed on these
    Data(PwKeyArray),
    Func(Box<Fn() -> PwKeyArray>)
}

#[derive(Debug)]
pub enum ValidateError {
    InvalidInputStream,
    InvalidOutputStream,
    PasswordTypeIsUnknown,
    PasswordIsEmpty,
    PasswordDataIsAllZero,
    BufferTooSmall,
}

pub struct Config {
    pub input_stream: InputStream,
    pub output_stream: OutputStream,
    pub output_format: OutputFormat,
    pub line_ending_encrypt: LineEndingOnEncrypt,
    pub line_ending_decrypt: LineEndingOnDecrypt,
    pub rng_mode: RngMode,
    pub initialization_vector: InitializationVector,
    pub password: PasswordType,
    pub salt: String,
    pub encryption_method: EncryptionMethod,
    pub buffer_size: usize,
    pub remove_input_after_encrypt: bool
}

pub fn slice_is_zeroed(d:&[u8]) -> bool {
    d.iter().find(|b| **b != 0).is_none()
}

pub fn default_scrypt_params() -> PasswordKeyGenMethod {
    // TODO: check these
    PasswordKeyGenMethod::Scrypt(ScryptLogN(4),ScryptR(4),ScryptP(4))
}

impl Config {
    pub fn new() -> Self {
        Config {
            input_stream: InputStream::Unknown,
            output_stream: OutputStream::Unknown,
            output_format: OutputFormat::EncryptFile,
            line_ending_encrypt: LineEndingOnEncrypt::Ignore,
            line_ending_decrypt: LineEndingOnDecrypt::Ignore,
            rng_mode: RngMode::OsIssac,
            initialization_vector: InitializationVector::GenerateFromRng,
            password: PasswordType::Unknown,
            salt: "DefaultSalt".to_owned(),
            encryption_method: EncryptionMethod::AesCbc256,
            buffer_size: 65536,
            remove_input_after_encrypt: false
        }
    }

    pub fn input_stream(&mut self, is:InputStream) -> &mut Self {
        self.input_stream = is;
        self
    }
    pub fn output_stream(&mut self, os:OutputStream) -> &mut Self {
        self.output_stream = os;
        self
    }
    pub fn line_ending_encrypt(&mut self, line_ending_encrypt:LineEndingOnEncrypt) -> &mut Self {
        self.line_ending_encrypt = line_ending_encrypt;
        self
    }
    pub fn line_ending_decrypt(&mut self, line_ending_decrypt:LineEndingOnDecrypt) -> &mut Self {
        self.line_ending_decrypt = line_ending_decrypt;
        self
    }
    pub fn rng_mode(&mut self, rng_mode:RngMode) -> &mut Self {
        self.rng_mode = rng_mode;
        self
    }
    pub fn initialization_vector(&mut self, initialization_vector:InitializationVector) -> &mut Self {
        self.initialization_vector = initialization_vector;
        self
    }
    pub fn password(&mut self, password:PasswordType) -> &mut Self {
        self.password = password;
        self
    }
    pub fn salt(&mut self, salt:String) -> &mut Self {
        self.salt = salt;
        self
    }
    pub fn encryption_method(&mut self, encryption_method:EncryptionMethod) -> &mut Self {
        self.encryption_method = encryption_method;
        self
    }
    pub fn buffer_size(&mut self, buffer_size:usize) -> &mut Self {
        self.buffer_size = buffer_size;
        self
    }
    pub fn remove_input_after_encrypt(&mut self, remove_input_after_encrypt:bool) -> &mut Self {
        self.remove_input_after_encrypt = remove_input_after_encrypt;
        self
    }
    pub fn validate(&self) -> Result<(),ValidateError> {
        if let InputStream::Unknown = self.input_stream {
            return Err(ValidateError::InvalidInputStream);
        }
        if let OutputStream::Unknown = self.output_stream {
            return Err(ValidateError::InvalidOutputStream);
        }
        match self.password {
            PasswordType::Unknown =>
                return Err(ValidateError::PasswordTypeIsUnknown),
            PasswordType::Cleartext(ref s, _) if s.is_empty() =>
                return Err(ValidateError::PasswordIsEmpty),

            PasswordType::Data(ref d) => {
                if slice_is_zeroed(d) {
                    return Err(ValidateError::PasswordDataIsAllZero)
                }
            },

            PasswordType::Func(_)
            | PasswordType::Cleartext(_, _) => (),
        }
        if self.buffer_size < 4096 {
            return Err(ValidateError::BufferTooSmall)
        }

        Ok(())
    }
}

#[test]
fn validate() {
    macro_rules! check {
        ( $c:expr, $case:path ) => {
            match $c.validate() {
                Err( $case ) => (),
                x => panic!("Unexpected validate error: {:?}", x)
            }
        }
    }
    macro_rules! check_ok {
        ( $c:expr ) => {
            match $c.validate() {
                Ok(_) => (),
                x => panic!("Unexpected validate error: {:?}", x)
            }
        }
    }

    let mut c = Config::new();

    check!(c, ValidateError::InvalidInputStream);
    c.input_stream(InputStream::Stdin);
    check!(c, ValidateError::InvalidOutputStream);
    c.output_stream(OutputStream::Stdout);
    check!(c, ValidateError::PasswordTypeIsUnknown);

    c.password(PasswordType::Cleartext("".to_owned(), default_scrypt_params()));
    check!(c, ValidateError::PasswordIsEmpty);
    c.password(PasswordType::Cleartext("    ".to_owned(), default_scrypt_params()));
    check_ok!(c);

    let mut pd:[u8; PW_KEY_SIZE] = [0; PW_KEY_SIZE];
    c.password(PasswordType::Data(pd));
    check!(c, ValidateError::PasswordDataIsAllZero);
    pd[0] = 1;
    c.password(PasswordType::Data(pd));
    check_ok!(c);

    c.buffer_size(0);
    check!(c, ValidateError::BufferTooSmall);
    c.buffer_size(4096);
    check_ok!(c);
}
