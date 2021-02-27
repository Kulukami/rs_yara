pub mod compile;
pub mod yara_c;

pub use self::compile::*;
pub use self::yara_c::*;


use std::error;
use std::fmt;
use std::os::raw::c_int;
use std::os::raw::c_char;


pub use yara_c::ERROR_CALLBACK_ERROR;
pub use yara_c::ERROR_CORRUPT_FILE;
pub use yara_c::ERROR_COULD_NOT_ATTACH_TO_PROCESS;
pub use yara_c::ERROR_COULD_NOT_MAP_FILE;
pub use yara_c::ERROR_COULD_NOT_OPEN_FILE;
pub use yara_c::ERROR_INSUFFICIENT_MEMORY;
pub use yara_c::ERROR_INTERNAL_FATAL_ERROR;
pub use yara_c::ERROR_INVALID_FILE;
pub use yara_c::ERROR_SCAN_TIMEOUT;
pub use yara_c::ERROR_SUCCESS;
pub use yara_c::ERROR_SYNTAX_ERROR;
pub use yara_c::ERROR_TOO_MANY_MATCHES;
pub use yara_c::ERROR_UNSUPPORTED_FILE_VERSION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Callback returned an error
    CallbackError,
    /// Rule file is corrupt
    CorruptFile,
    /// Could not attach to process
    CouldNotAttach,
    /// File could not be mapped into memory
    CouldNotMapFile,
    /// File could not be opened
    CouldNotOpenFile,
    /// Insufficient memory to complete the operation
    InsufficientMemory,
    /// Internal fatal error
    InternalFatalError,
    /// File is not a valid rules file
    InvalidFile,
    /// Timeouted during scan
    ScanTimeout,
    /// Syntax error in rule
    SyntaxError,
    /// Too many matches
    TooManyMatches,
    /// Rule file version is not supported
    UnsupportedFileVersion,
    /// Unknown Yara error
    Unknown(i32),
}

impl Error {
    pub fn from_code(code: c_int) -> Result<(), Error> {
        use self::Error::*;

        if code as u32 == ERROR_SUCCESS {
            return Ok(());
        }

        Err(match code as u32 {
            ERROR_CALLBACK_ERROR => CallbackError,
            ERROR_CORRUPT_FILE => CorruptFile,
            ERROR_COULD_NOT_ATTACH_TO_PROCESS => CouldNotAttach,
            ERROR_COULD_NOT_MAP_FILE => CouldNotMapFile,
            ERROR_COULD_NOT_OPEN_FILE => CouldNotOpenFile,
            ERROR_INSUFFICIENT_MEMORY => InsufficientMemory,
            ERROR_INTERNAL_FATAL_ERROR => InternalFatalError,
            ERROR_INVALID_FILE => InvalidFile,
            ERROR_SCAN_TIMEOUT => ScanTimeout,
            ERROR_SYNTAX_ERROR => SyntaxError,
            ERROR_TOO_MANY_MATCHES => TooManyMatches,
            ERROR_UNSUPPORTED_FILE_VERSION => UnsupportedFileVersion,
            _ => Unknown(code),
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.clone().into())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        self.clone().into()
    }
}

impl From<Error> for &'static str {
    fn from(error: Error) -> &'static str {
        use self::Error::*;

        match error {
            CallbackError => "Callback returned an error",
            CorruptFile => "Rule file is corrupt",
            CouldNotAttach => "Could not attach to process",
            CouldNotMapFile => "File could not be mapped into memory",
            CouldNotOpenFile => "File could not be opened",
            InsufficientMemory => "Insufficient memory to complete the operation",
            InternalFatalError => "Internal fatal error",
            InvalidFile => "File is not a valid rules file",
            ScanTimeout => "Timeouted during scan",
            SyntaxError => "Syntax error in rule",
            TooManyMatches => "Too many matches",
            UnsupportedFileVersion => "Rule file version is not supported",
            Unknown(_) => "Unknown Yara error",
        }
    }
}



pub mod scan_flags {
    pub use super::{SCAN_FLAGS_FAST_MODE, SCAN_FLAGS_PROCESS_MEMORY, SCAN_FLAGS_NO_TRYCATCH};
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaType {
    Null,
    Integer,
    String,
    Boolean,
}

impl MetaType {
    pub fn from_code(code: i32) -> Result<Self, i32> {
        use self::MetaType::*;
        match code as u32 {
            META_TYPE_NULL => Ok(Null),
            META_TYPE_INTEGER => Ok(Integer),
            META_TYPE_STRING => Ok(String),
            META_TYPE_BOOLEAN => Ok(Boolean),
            _ => Err(code),
        }
    }
}

// TODO: Find a better way than accessing anonymous fields or use flag yara 3.7 or something else.
impl YR_MATCHES {
    pub fn get_head(&self) -> *const YR_MATCH {
        unsafe { self.__bindgen_anon_1.head }
    }

    pub fn get_tail(&self) -> *const YR_MATCH {
        unsafe { self.__bindgen_anon_2.tail }
    }
}

impl YR_META {
    pub fn get_identifier(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.identifier }
    }

    pub fn get_string(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_2.string }
    }
}

impl YR_NAMESPACE {
    pub fn get_name(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.name }
    }
}

impl YR_RULE {
    pub fn get_identifier(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.identifier }
    }

    pub fn get_tags(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_2.tags }
    }

    pub fn get_metas(&self) -> *const YR_META {
        unsafe { self.__bindgen_anon_3.metas }
    }

    pub fn get_strings(&self) -> *const YR_STRING {
        unsafe { self.__bindgen_anon_4.strings }
    }

    pub fn get_ns(&self) -> *const YR_NAMESPACE {
        unsafe { self.__bindgen_anon_5.ns }
    }
}

impl YR_STRING {
    pub fn get_identifier(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.identifier }
    }

    pub fn get_string(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_2.string as _ }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_from_code() {
        use super::Error::*;

        assert_eq!(Ok(()), Error::from_code(ERROR_SUCCESS as i32));
        assert_eq!(
            Err(InsufficientMemory),
            Error::from_code(ERROR_INSUFFICIENT_MEMORY as i32)
        );
        assert_eq!(
            Err(ScanTimeout),
            Error::from_code(ERROR_SCAN_TIMEOUT as i32)
        );
    }

    #[test]
    fn test_to_string() {
        use std::error::Error as StdError;
        assert_eq!(
            "Callback returned an error",
            Error::CallbackError.to_string()
        );
        assert_eq!(
            "Callback returned an error",
            Error::CallbackError.description()
        );
    }
}
