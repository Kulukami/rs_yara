use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::marker;
use std::os::raw::c_char;
use std::ptr;

use std::convert::TryFrom;
use std::fs::File;
use std::path::Path;
use  crate::{initialize::InitializationToken, meta::MetadataIterator, rules_scan_file, rules_scan_mem, string::{YrString, YrStringIterator}, yara_sys::{self, scan_flags::*}};

use crate::errors::*;

pub struct Rules {
    inner: *mut yara_sys::YR_RULES,
    pub(crate) _token: InitializationToken,
    flags: u32,
}

/// This is safe because Yara have a mutex on the YR_RULES
unsafe impl std::marker::Sync for Rules {}

impl TryFrom<*mut yara_sys::YR_RULES> for Rules {
    type Error = YaraError;

    fn try_from(rules: *mut yara_sys::YR_RULES) -> Result<Self, Self::Error> {
        let token = InitializationToken::new()?;

        Ok(Rules {
            inner: rules,
            _token: token,
            flags: 0,
        })
    }
}

impl Rules {
    pub fn scan_mem(&self, mem: &[u8], timeout: u16) -> Result<Vec<Rule>, YaraError> {
        // The token needed here because scanning allocate space for regexp on the thread_local
        // storage before 3.8.
        let _token = InitializationToken::new()?;

        rules_scan_mem(self.inner, mem, i32::from(timeout), self.flags as i32)
    }

    /// Scan a file.
    ///
    /// Return a `Vec` of matching rules.
    pub fn scan_file<'r, P: AsRef<Path>>(
        &self,
        path: P,
        timeout: u16,
    ) -> Result<Vec<Rule<'r>>, Error> {
        // The token needed here because scanning allocate space for regexp on the thread_local
        // storage before 3.8.
        let _token = InitializationToken::new()?;

        File::open(path)
            .map_err(|e| IoError::new(e, IoErrorKind::OpenScanFile).into())
            .and_then(|file| {
                rules_scan_file(self.inner, &file, i32::from(timeout), self.flags as i32)
                    .map_err(|e| e.into())
            })
    }

    /// Save the rules to a file.
    ///
    /// Note: this method is mut because Yara modifies the Rule arena during serialization.
    // TODO Take AsRef<Path> ?
    // Yara is expecting a *const u8 string, whereas a Path on Windows is an [u16].
    pub fn save(&mut self, filename: &str) -> Result<(), YaraError> {
        rules_save(self.inner, filename)
    }

    /// Save the rules in a Writer.
    ///
    /// Note: this method is mut because Yara modifies the Rule arena during serialization.
    pub fn save_to_stream<W>(&mut self, writer: W) -> Result<(), Error>
    where
        W: Write,
    {
        rules_save_stream(self.inner, writer)
    }

    /// Load rules from a pre-compiled rules file.
    pub fn load_from_stream<R: Read>(reader: R) -> Result<Self, Error> {
        let token = InitializationToken::new()?;

        rules_load_stream(reader).map(|inner| Rules {
            inner,
            _token: token,
            flags: 0,
        })
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Take AsRef<Path> ?
    pub fn load_from_file(filename: &str) -> Result<Self, YaraError> {
        let token = InitializationToken::new()?;

        rules_load(filename).map(|inner| Rules {
            inner,
            _token: token,
            flags: 0,
        })
    }

    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        rules_destroy(self.inner);
    }
}

/// A rule that matched during a scan.
#[derive(Debug)]
pub struct Rule<'r> {
    /// Name of the rule.
    pub identifier: &'r str,
    /// Namespace of the rule.
    pub namespace: &'r str,
    /// Metadatas of the rule.
    pub metadatas: Vec<Metadata<'r>>,
    /// Tags of the rule.
    pub tags: Vec<&'r str>,
    /// Matcher strings of the rule.
    pub strings: Vec<YrString<'r>>,
}

/// Metadata specified in a rule.
#[derive(Debug, Eq, PartialEq)]
pub struct Metadata<'r> {
    pub identifier: &'r str,
    pub value: MetadataValue<'r>,
}

/// Type of the value in [MetaData](struct.Metadata.html)
#[derive(Debug, Eq, PartialEq)]
pub enum MetadataValue<'r> {
    Integer(i64),
    String(&'r str),
    Boolean(bool),
}


pub fn rules_destroy(rules: *mut yara_sys::YR_RULES) {
    unsafe {
        yara_sys::yr_rules_destroy(rules);
    }
}

// TODO Check if non mut
pub fn rules_save(rules: *mut yara_sys::YR_RULES, filename: &str) -> Result<(), YaraError> {
    let filename = CString::new(filename).unwrap();
    let result = unsafe { yara_sys::yr_rules_save(rules, filename.as_ptr()) };
    yara_sys::Error::from_code(result).map_err(|e| e.into())
}

pub fn rules_save_stream<W>(rules: *mut yara_sys::YR_RULES, mut writer: W) -> Result<(), Error>
where
    W: Write,
{
    let mut write_stream = super::stream::WriteStream::new(&mut writer);
    let mut yr_stream = write_stream.as_yara();
    let result = unsafe { yara_sys::yr_rules_save_stream(rules, &mut yr_stream) };

    write_stream
        .result()
        .map_err(|e| IoError::new(e, IoErrorKind::WritingRules).into())
        .and_then(|_| {
            yara_sys::Error::from_code(result)
                .map_err(From::from)
                .map_err(|e: YaraError| e.into())
        })
}

pub fn rules_load(filename: &str) -> Result<*mut yara_sys::YR_RULES, YaraError> {
    let filename = CString::new(filename).unwrap();
    let mut pointer: *mut yara_sys::YR_RULES = ptr::null_mut();
    let result = unsafe { yara_sys::yr_rules_load(filename.as_ptr(), &mut pointer) };
    yara_sys::Error::from_code(result)
        .map(|()| pointer)
        .map_err(|e| e.into())
}

pub fn rules_load_stream<R>(mut reader: R) -> Result<*mut yara_sys::YR_RULES, Error>
where
    R: Read,
{
    let mut read_stream = super::stream::ReadStream::new(&mut reader);
    let mut yr_stream = read_stream.as_yara();
    let mut pointer: *mut yara_sys::YR_RULES = ptr::null_mut();
    let result = unsafe { yara_sys::yr_rules_load_stream(&mut yr_stream, &mut pointer) };

    read_stream
        .result()
        .map(|()| pointer)
        .map_err(|e| IoError::new(e, IoErrorKind::ReadingRules).into())
        .and_then(|pointer| {
            yara_sys::Error::from_code(result)
                .map(|_| pointer)
                .map_err(From::from)
                .map_err(|e: YaraError| e.into())
        })
}

impl<'a> From<&'a yara_sys::YR_RULE> for Rule<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> Self {
        let identifier = unsafe { CStr::from_ptr(rule.get_identifier()) }
            .to_str()
            .unwrap();
        let namespace = unsafe { CStr::from_ptr((&*rule.get_ns()).get_name()) }
            .to_str()
            .unwrap();
        let metadatas = MetadataIterator::from(rule).map(Metadata::from).collect();
        let tags = TagIterator::from(rule)
            .map(|c| c.to_str().unwrap())
            .collect();
        let strings = YrStringIterator::from(rule).map(YrString::from).collect();

        Rule {
            identifier,
            namespace,
            metadatas,
            tags,
            strings,
        }
    }
}

struct TagIterator<'a> {
    head: *const c_char,
    _marker: marker::PhantomData<&'a c_char>,
}

impl<'a> From<&'a yara_sys::YR_RULE> for TagIterator<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> Self {
        TagIterator {
            head: rule.get_tags(),
            _marker: Default::default(),
        }
    }
}

impl<'a> Iterator for TagIterator<'a> {
    type Item = &'a CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.head.is_null() && unsafe { *self.head } != 0 {
            let s = unsafe { CStr::from_ptr(self.head) };
            self.head = unsafe { self.head.add(s.to_bytes_with_nul().len()) };
            Some(s)
        } else {
            None
        }
    }
}
