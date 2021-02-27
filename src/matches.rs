use std::marker;
use std::slice;

use crate::yara_sys;

/// A match within a scan.
#[derive(Debug)]
pub struct Match {
    /// Offset of the match within the scanning area.
    pub offset: usize,
    /// Length of the file. Can be useful if the matcher string has not a fixed length.
    pub length: usize,
    /// Matched data.
    pub data: Vec<u8>,
}


/// Iterate over YR_MATCH in a YR_MATCHES
///
/// # Implementation notes
///
/// See `yr_string_matches_foreach` in Yara.
pub struct MatchIterator<'a> {
    head: *const yara_sys::YR_MATCH,
    _marker: marker::PhantomData<&'a yara_sys::YR_MATCH>,
}

impl<'a> From<&'a yara_sys::YR_MATCHES> for MatchIterator<'a> {
    fn from(matches: &'a yara_sys::YR_MATCHES) -> MatchIterator<'a> {
        MatchIterator {
            head: matches.get_head(),
            _marker: marker::PhantomData::default(),
        }
    }
}

impl<'a> Iterator for MatchIterator<'a> {
    type Item = &'a yara_sys::YR_MATCH;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.head.is_null() {
            let m = unsafe { &*self.head };
            self.head = m.next;
            Some(m)
        } else {
            None
        }
    }
}

impl<'a> From<&'a yara_sys::YR_MATCH> for Match {
    fn from(m: &yara_sys::YR_MATCH) -> Self {
        Match {
            offset: m.offset as usize,
            length: m.match_length as usize,
            data: Vec::from(unsafe { slice::from_raw_parts(m.data, m.data_length as usize) }),
        }
    }
}
