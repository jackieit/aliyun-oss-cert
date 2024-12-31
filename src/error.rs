use reqwest::Error as ReqwestError;
use serde_json::Error as JsonError;
use std::fmt;
use std::io::Error as IoError;
use std::string::FromUtf8Error as Utf8Error;
use std::time::SystemTimeError as TimeError;

#[derive(Debug)]
pub struct Error(String, String);

impl Error {
    pub fn new(kind: String, message: String) -> Error {
        Error(kind, message)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IpTellDnspod Error: From {}, {}", self.0, self.1)
    }
}
impl std::error::Error for Error {}
impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Error::new("StdIo".to_string(), err.to_string())
    }
}
impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        Error::new("FromUtf8".to_string(), err.to_string())
    }
}
impl From<TimeError> for Error {
    fn from(err: TimeError) -> Self {
        Error::new("SystemTime".to_string(), err.to_string())
    }
}
impl From<JsonError> for Error {
    fn from(err: JsonError) -> Self {
        Error::new("JsonConvert".to_string(), err.to_string())
    }
}
impl From<serde_xml_rs::Error> for Error {
    fn from(err: serde_xml_rs::Error) -> Self {
        Error::new("XmlConvert".to_string(), err.to_string())
    }
}
impl From<ReqwestError> for Error {
    fn from(err: ReqwestError) -> Self {
        Error::new("Reqwest".to_string(), err.to_string())
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        Error::new("AddrParse".to_string(), err.to_string())
    }
}
