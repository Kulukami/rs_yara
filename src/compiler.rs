use std::{convert::TryFrom, ffi::{CStr, CString}};
use std::fs::File;
use std::os::raw::{c_char, c_int, c_void};

use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;

use yara_sys::{YR_COMPILER, YR_RULES};

use crate::{Rules, errors::*, initialize::InitializationToken, yara_sys};

pub fn compiler_create<'a>() -> Result<&'a mut YR_COMPILER, YaraError> {
    let mut pointer: *mut YR_COMPILER = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_create(&mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| unsafe { &mut *pointer })
        .map_err(|e| e.into())
}

pub fn compiler_destroy(compiler_ptr: *mut YR_COMPILER) {
    unsafe {
        yara_sys::yr_compiler_destroy(compiler_ptr);
    }
}

pub fn compiler_add_string(
    compiler: *mut YR_COMPILER,
    string: &str,
    namespace: Option<&str>,
) -> Result<(), Error> {
    let string = CString::new(string).unwrap();
    let namespace = namespace.map(|n| CString::new(n).unwrap());
    let mut errors = Vec::<CompileError>::new();
    unsafe {
        yara_sys::yr_compiler_set_callback(
            compiler,
            Some(compile_callback),
            &mut errors as *mut Vec<_> as _,
        )
    };
    let result = unsafe {
        yara_sys::yr_compiler_add_string(
            compiler,
            string.as_ptr(),
            namespace.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
        )
    };

    compile_result(result, errors)
}

pub fn compiler_add_file<P: AsRef<Path>>(
    compiler: *mut YR_COMPILER,
    file: &File,
    path: P,
    namespace: Option<&str>,
) -> Result<(), Error> {
    // TODO: Improve. WTF.
    let path = CString::new(path.as_ref().as_os_str().to_str().unwrap()).unwrap();
    let namespace = namespace.map(|n| CString::new(n).unwrap());
    let mut errors = Vec::<CompileError>::new();
    unsafe {
        yara_sys::yr_compiler_set_callback(
            compiler,
            Some(compile_callback),
            &mut errors as *mut Vec<_> as _,
        )
    };
    let result = compiler_add_file_raw(compiler, file, &path, namespace.as_deref());

    compile_result(result, errors)
}

fn compile_result(compile_result: i32, messages: Vec<CompileError>) -> Result<(), Error> {
    if compile_result == 0 || messages.iter().all(|c| c.level != CompileErrorLevel::Error) {
        Ok(())
    } else {
        Err(CompileErrors::new(messages).into())
    }
}

#[cfg(unix)]
fn compiler_add_file_raw(
    compiler: *mut YR_COMPILER,
    file: &File,
    path: &CStr,
    namespace: Option<&CStr>,
) -> i32 {
    let fd = file.as_raw_fd();
    unsafe {
        yara_sys::yr_compiler_add_fd(
            compiler,
            fd,
            namespace.map_or(ptr::null(), CStr::as_ptr),
            path.as_ptr(),
        )
    }
}

extern "C" fn compile_callback(
    error_level: c_int,
    filename: *const c_char,
    line_number: c_int,
    message: *const c_char,
    user_data: *mut c_void,
) {
    let errors: &mut Vec<CompileError> = unsafe { &mut *(user_data as *mut Vec<CompileError>) };
    let message = unsafe { CStr::from_ptr(message) }.to_str().unwrap();
    let filename = if !filename.is_null() {
        Some(unsafe { CStr::from_ptr(filename) }.to_str().unwrap())
    } else {
        None
    };
    errors.push(CompileError {
        level: CompileErrorLevel::from_code(error_level),
        filename: filename.map(|s| s.to_string()),
        line: line_number as usize,
        message: message.to_owned(),
    });
}

pub fn compiler_define_integer_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: i64,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_integer_variable(compiler, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_float_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: f64,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_float_variable(compiler, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_boolean_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: bool,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let value = if value { 1 } else { 0 };
    let result = unsafe {
        yara_sys::yr_compiler_define_boolean_variable(compiler, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_str_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: &str,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let value = CString::new(value).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_string_variable(compiler, identifier.as_ptr(), value.as_ptr())
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_cstr_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: &CStr,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_string_variable(compiler, identifier.as_ptr(), value.as_ptr())
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_get_rules(compiler: *mut YR_COMPILER) -> Result<*mut YR_RULES, YaraError> {
    let mut pointer = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_get_rules(compiler, &mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| pointer)
        .map_err(Into::into)
}

/// Yara rules compiler
pub struct Compiler {
    inner: *mut yara_sys::YR_COMPILER,
    _token: InitializationToken,
}

impl Compiler {
    /// Create a new compiler.
    pub fn new() -> Result<Self, YaraError> {
        let token = InitializationToken::new()?;

        compiler_create().map(|inner| Compiler {
            inner,
            _token: token,
        })
    }

    pub fn add_rules_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        File::open(path.as_ref())
            .map_err(|e| IoError::new(e, IoErrorKind::OpenRulesFile).into())
            .and_then(|file| compiler_add_file(self.inner, &file, path, None))
    }


    pub fn add_rules_file_with_namespace<P: AsRef<Path>>(
        &mut self,
        path: P,
        namespace: &str,
    ) -> Result<(), Error> {
        File::open(path.as_ref())
            .map_err(|e| IoError::new(e, IoErrorKind::OpenRulesFile).into())
            .and_then(|file| compiler_add_file(self.inner, &file, path, Some(namespace)))
    }

    pub fn add_rules_str(&mut self, rule: &str) -> Result<(), Error> {
        compiler_add_string(self.inner, rule, None)
    }

    pub fn add_rules_str_with_namespace(
        &mut self,
        rule: &str,
        namespace: &str,
    ) -> Result<(), Error> {
        compiler_add_string(self.inner, rule, Some(namespace))
    }

    
    pub fn compile_rules(self) -> Result<Rules, YaraError> {
        compiler_get_rules(self.inner).and_then(Rules::try_from)
    }

    pub fn define_variable<V: CompilerVariableValue>(
        &mut self,
        identifier: &str,
        value: V,
    ) -> Result<(), YaraError> {
        value.add_to_compiler(self.inner, identifier)
    }
}

impl Drop for Compiler {
    fn drop(&mut self) {
        compiler_destroy(self.inner);
    }
}

/// Trait implemented by the types the compiler can use as value.
pub trait CompilerVariableValue {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError>;
}

impl CompilerVariableValue for bool {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        compiler_define_boolean_variable(compiler, identifier, *self)
    }
}

impl CompilerVariableValue for f64 {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        compiler_define_float_variable(compiler, identifier, *self)
    }
}

impl CompilerVariableValue for i64 {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        compiler_define_integer_variable(compiler, identifier, *self)
    }
}

impl CompilerVariableValue for &str {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        compiler_define_str_variable(compiler, identifier, *self)
    }
}

impl CompilerVariableValue for &CStr {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        compiler_define_cstr_variable(compiler, identifier, *self)
    }
}
