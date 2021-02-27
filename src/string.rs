use std::ffi::CStr;
use std::marker;

use crate::{get_tidx, matches::{Match, MatchIterator}, yara_sys};

#[derive(Debug)]
pub struct YrString<'a> {
    /// Name of the string, with the '$'.
    pub identifier: &'a str,
    /// Matches of the string for the scan.
    pub matches: Vec<Match>,
}

pub struct YrStringIterator<'a> {
    head: *const yara_sys::YR_STRING,
    _marker: marker::PhantomData<&'a yara_sys::YR_STRING>,
}

impl<'a> From<&'a yara_sys::YR_RULE> for YrStringIterator<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> YrStringIterator<'a> {
        YrStringIterator {
            head: rule.get_strings(),
            _marker: marker::PhantomData::default(),
        }
    }
}

impl<'a> Iterator for YrStringIterator<'a> {
    type Item = &'a yara_sys::YR_STRING;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        let string = unsafe { &*self.head };

        if string.g_flags as u32 & yara_sys::STRING_GFLAGS_NULL != 0 {
            None
        } else {
            self.head = unsafe { self.head.offset(1) };
            Some(string)
        }
    }
}

impl<'a> From<&'a yara_sys::YR_STRING> for YrString<'a> {
    fn from(string: &yara_sys::YR_STRING) -> Self {
        let identifier = unsafe { CStr::from_ptr(string.get_identifier()) }
            .to_str()
            .unwrap();
        let tidx = get_tidx();
        let matches = MatchIterator::from(&string.matches[tidx as usize])
            .map(Match::from)
            .collect();

        YrString {
            identifier,
            matches,
        }
    }
}
