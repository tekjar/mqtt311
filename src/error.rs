use std::result;
use std::io;
use std::string::FromUtf8Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Fail, From)]
pub enum Error {
    #[fail(display = "Incorrect packet format")]
    IncorrectPacketFormat,
    #[fail(display = "Invalid topic path")]
    InvalidTopicPath,
    #[fail(display = "Unsupported protocol name")]
    UnsupportedProtocolName,
    #[fail(display = "Unsupported protocol version")]
    UnsupportedProtocolVersion,
    #[fail(display = "Unsupported QoS")]
    UnsupportedQualityOfService,
    #[fail(display = "Unsupported packet type")]
    UnsupportedPacketType,
    #[fail(display = "Unsupported connect return code")]
    UnsupportedConnectReturnCode,
    #[fail(display = "Incorrect payload size")]
    PayloadSizeIncorrect,
    #[fail(display = "Payload too long")]
    PayloadTooLong,
    #[fail(display = "Payload required")]
    PayloadRequired,
    #[fail(display = "Topic name doesn't support non utf-8")]
    TopicNameMustNotContainNonUtf8(FromUtf8Error),
    #[fail(display = "Topic name shouldn't contain wild card")]
    TopicNameMustNotContainWildcard,
    #[fail(display = "Incorrect remaining length")]
    MalformedRemainingLength,
    #[fail(display = "Unexpected EOF")]
    UnexpectedEof,
    #[fail(display = "Io failed. Error = {}", _0)]
    Io(io::Error)
}

