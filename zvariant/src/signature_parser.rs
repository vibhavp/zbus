use std::ops::{Bound, RangeBounds, RangeFrom, RangeTo};

use nom::{
    branch::alt,
    character::complete::{char, satisfy},
    combinator::{cut, recognize},
    error::{ContextError, ParseError},
    multi::many1_count,
    sequence::{delimited, pair, preceded},
    AsChar, IResult, InputIter, InputLength, Offset, Slice,
};

use crate::{subslice, Basic, ObjectPath, Result, Signature, STRUCT_SIG_END_CHAR};

#[cfg(unix)]
use crate::Fd;

#[cfg(feature = "gvariant")]
use crate::utils::MAYBE_SIGNATURE_CHAR;
use crate::utils::{
    ARRAY_SIGNATURE_CHAR, DICT_ENTRY_SIG_END_CHAR, DICT_ENTRY_SIG_START_CHAR,
    STRUCT_SIG_START_CHAR, VARIANT_SIGNATURE_CHAR,
};

#[derive(Debug, Clone)]
pub(crate) struct SignatureParser<'s> {
    signature: Signature<'s>,
    pos: usize,
    end: usize,
}

impl<'s> SignatureParser<'s> {
    pub fn new(signature: Signature<'s>) -> Self {
        let end = signature.len();

        Self {
            signature,
            pos: 0,
            end,
        }
    }

    pub fn signature(&self) -> Signature<'_> {
        self.signature.slice(self.pos..self.end)
    }

    pub fn next_char(&self) -> Result<char> {
        subslice(self.signature.as_bytes(), self.pos).map(|b| *b as char)
    }

    #[inline]
    pub fn skip_char(&mut self) -> Result<()> {
        self.skip_chars(1)
    }

    pub fn skip_chars(&mut self, num_chars: usize) -> Result<()> {
        self.pos += num_chars;

        // We'll be going one char beyond at the end of parsing but not beyond that.
        if self.pos > self.end {
            return Err(serde::de::Error::invalid_length(
                self.signature.len(),
                &format!(">= {} characters", self.pos).as_str(),
            ));
        }

        Ok(())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.pos
    }

    #[inline]
    pub fn done(&self) -> bool {
        self.pos == self.end
    }

    /// Returns a slice of `self` for the provided range.
    ///
    /// # Panics
    ///
    /// Requires that begin <= end and end <= self.len(), otherwise slicing will panic.
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        let len = self.len();

        let pos = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n + 1,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(&n) => n + 1,
            Bound::Excluded(&n) => n,
            Bound::Unbounded => len,
        };

        assert!(
            pos <= end,
            "range start must not be greater than end: {:?} > {:?}",
            pos,
            end,
        );
        assert!(end <= len, "range end out of bounds: {:?} > {:?}", end, len,);

        let mut clone = self.clone();
        clone.pos += pos;
        clone.end = self.pos + end;

        clone
    }

    /// Get the next signature and increment the position.
    pub fn parse_next_signature(&mut self) -> Result<Signature<'s>> {
        let len = &self.next_signature()?.len();
        let pos = self.pos;
        self.pos += len;

        // We'll be going one char beyond at the end of parsing but not beyond that.
        if self.pos > self.end {
            return Err(serde::de::Error::invalid_length(
                self.signature.len(),
                &format!(">= {} characters", self.pos).as_str(),
            ));
        }

        Ok(self.signature.slice(pos..self.pos))
    }

    /// Get the next signature but don't increment the position.
    pub fn next_signature(&self) -> Result<Signature<'_>> {
        match signature::<_, nom::error::Error<_>>(self.signature().as_str()) {
            Ok((_, output)) => Ok(self.signature_slice(0, output.len())),
            Err(e) => Err(crate::Error::Message(e.to_string())),
        }
    }

    fn signature_slice(&self, idx: usize, end: usize) -> Signature<'_> {
        self.signature.slice(self.pos + idx..self.pos + end)
    }
}

fn is_basic_type_signature<I: AsChar>(input: I) -> bool {
    match input.as_char() {
        u8::SIGNATURE_CHAR
        | bool::SIGNATURE_CHAR
        | i16::SIGNATURE_CHAR
        | u16::SIGNATURE_CHAR
        | i32::SIGNATURE_CHAR
        | u32::SIGNATURE_CHAR
        | i64::SIGNATURE_CHAR
        | u64::SIGNATURE_CHAR
        | f64::SIGNATURE_CHAR
        | <&str>::SIGNATURE_CHAR
        | ObjectPath::SIGNATURE_CHAR
        | Signature::SIGNATURE_CHAR
        | VARIANT_SIGNATURE_CHAR => true,
        #[cfg(unix)]
        Fd::SIGNATURE_CHAR => true,
        _ => false,
    }
}

fn signature<I, E>(input: I) -> IResult<I, I, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone + Offset + Slice<RangeTo<usize>> + Slice<RangeFrom<usize>> + InputIter + InputLength,
    <I as InputIter>::Item: AsChar,
{
    let array_signature = recognize(preceded(char(ARRAY_SIGNATURE_CHAR), cut(signature)));

    let struct_signature = recognize(delimited(
        char(STRUCT_SIG_START_CHAR),
        cut(many1_count(signature)),
        cut(char(STRUCT_SIG_END_CHAR)),
    ));

    let dict_entry_signature = recognize(delimited(
        char(DICT_ENTRY_SIG_START_CHAR),
        cut(pair(satisfy(is_basic_type_signature), signature)),
        cut(char(DICT_ENTRY_SIG_END_CHAR)),
    ));

    #[cfg(feature = "gvariant")]
    let maybe_signature = recognize(preceded(char(MAYBE_SIGNATURE_CHAR), cut(signature)));

    #[cfg(not(feature = "gvariant"))]
    let maybe_signature = nom::combinator::fail;

    alt((
        recognize(satisfy(is_basic_type_signature)),
        array_signature,
        struct_signature,
        dict_entry_signature,
        maybe_signature,
    ))(input)
}
