#![allow(non_camel_case_types)]
#![allow(non_snake_case)]


use std::sync::Mutex;
use lazy_static::lazy_static;
lazy_static! {
    static ref INIT_MUTEX: Mutex<()> = Mutex::new(());
}


pub mod yara_sys;
pub mod meta;
pub mod errors;


mod compiler;
mod initialize;
mod matches;
mod rules;
mod string;
mod scan;
mod stream;



use crate::initialize::InitializationToken;

pub use self::compiler::*;
pub use self::rules::*;
pub use self::scan::*;

use crate::errors::*;



pub fn initialize() -> Result<(), YaraError> {
    let _guard = INIT_MUTEX.lock();
    let result = unsafe { yara_sys::yr_initialize() };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn finalize() -> Result<(), YaraError> {
    let _guard = INIT_MUTEX.lock();
    let result = unsafe { yara_sys::yr_finalize() };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn finalize_thread() {
    unsafe { yara_sys::yr_finalize_thread() };
}

/// Get the Yara thread id.
pub fn get_tidx() -> i32 {
    unsafe { yara_sys::yr_get_tidx() }
}


pub struct Yara {
    _token: InitializationToken,
}

impl Yara {
    /// Create and initialize the library.
    pub fn new() -> Result<Yara, YaraError> {
        InitializationToken::new().map(|token| Yara { _token: token })
    }

    /// Create and initialize the library.
    #[deprecated = "Use new"]
    pub fn create() -> Result<Yara, YaraError> {
        Self::new()
    }

    /// Create a new compiler.
    #[deprecated = "Use Compiler::new"]
    pub fn new_compiler(&self) -> Result<Compiler, YaraError> {
        Compiler::new()
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Take AsRef<Path> ?
    #[deprecated = "Use Rules::load_from_file"]
    pub fn load_rules(&self, filename: &str) -> Result<Rules, YaraError> {
        Rules::load_from_file(filename)
    }
}
