use std::borrow::Cow;

#[derive(Clone, Debug)]
pub struct Error(Cow<'static, str>);

impl Error {
    pub fn from_cow(s: Cow<'static, str>) -> Self {
        Error(s)
    }
    pub fn into_cow(self) -> Cow<'static, str> {
        self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "pkcs8")]
impl From<pkcs8::Error> for Error {
    fn from(e: pkcs8::Error) -> Self {
        Error::from_cow(Cow::Owned(e.to_string()))
    }
}

#[cfg(feature = "pkcs8")]
impl From<pkcs8_0_11::Error> for Error {
    fn from(e: pkcs8_0_11::Error) -> Self {
        Error::from_cow(Cow::Owned(e.to_string()))
    }
}

#[cfg(feature = "signature")]
impl From<signature::Error> for Error {
    fn from(e: signature::Error) -> Self {
        Error::from_cow(Cow::Owned(e.to_string()))
    }
}

#[cfg(feature = "signature")]
impl From<signature_3::Error> for Error {
    fn from(e: signature_3::Error) -> Self {
        Error::from_cow(Cow::Owned(e.to_string()))
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(e: std::array::TryFromSliceError) -> Self {
        Error::from_cow(Cow::Owned(e.to_string()))
    }
}

#[macro_export]
macro_rules! error {
    ($fmt:literal) => {
        $crate::Error::from_cow(std::borrow::Cow::Borrowed($fmt))
    };
    ($fmt:literal, $($arg:tt)*) => {
        $crate::Error::from_cow(std::borrow::Cow::Owned(format!($fmt, $($arg)*)))
    };
}

#[macro_export]
macro_rules! bail {
    ($fmt:literal) => {{
        return Err($crate::error!($fmt));
    }};
    ($fmt:literal, $($arg:tt)*) => {{
        return Err($crate::error!($fmt, $($arg)*));
    }};
}

#[macro_export]
macro_rules! ensure {
    ($condition: expr, $fmt:literal) => {
        if !$condition {
            $crate::bail!($fmt);
        }
    };
    ($condition: expr, $fmt:literal, $($arg:tt)*) => {
        if !$condition {
            $crate::bail!($fmt, $($arg)*);
        }
    };
}
