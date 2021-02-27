use std::ffi::CStr;
use std::marker;

use crate::{Metadata, MetadataValue, yara_sys};

pub struct MetadataIterator<'a> {
    head: *const yara_sys::YR_META,
    _marker: marker::PhantomData<&'a yara_sys::YR_STRING>,
}

impl<'a> From<&'a yara_sys::YR_RULE> for MetadataIterator<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> Self {
        MetadataIterator {
            head: rule.get_metas(),
            _marker: Default::default(),
        }
    }
}

impl<'a> Iterator for MetadataIterator<'a> {
    type Item = &'a yara_sys::YR_META;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.head.is_null() {
            let meta = unsafe { &*self.head };
            let t = yara_sys::MetaType::from_code(meta.type_).unwrap();
            if t != yara_sys::MetaType::Null {
                self.head = unsafe { self.head.offset(1) };
                return Some(meta);
            }
        }

        None
    }
}

impl<'a> From<&'a yara_sys::YR_META> for Metadata<'a> {
    fn from(meta: &'a yara_sys::YR_META) -> Self {
        let identifier = unsafe { CStr::from_ptr(meta.get_identifier()) }
            .to_str()
            .unwrap();
        let t = yara_sys::MetaType::from_code(meta.type_).unwrap();
        let value = match t {
            yara_sys::MetaType::Boolean => MetadataValue::Boolean(meta.integer != 0),
            yara_sys::MetaType::Integer => MetadataValue::Integer(meta.integer),
            yara_sys::MetaType::String => MetadataValue::String(
                unsafe { CStr::from_ptr(meta.get_string()) }
                    .to_str()
                    .unwrap(),
            ),
            yara_sys::MetaType::Null => unreachable!(),
        };
        Metadata { identifier, value }
    }
}
