use std::fmt;

/// Rejection stages remain distinct from source-language undefined behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    Framing,
    Wire,
    Resource,
    Semantic,
    UnavailableEvidence,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Framing => "framing",
            Self::Wire => "wire",
            Self::Resource => "resource",
            Self::Semantic => "semantic",
            Self::UnavailableEvidence => "unavailable-evidence",
        }
    }
}

/// A symbolic diagnostic and bounded source context; never a success token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    class: ErrorClass,
    code: &'static str,
    context: String,
}

impl Error {
    pub(crate) fn new(class: ErrorClass, code: &'static str, context: impl Into<String>) -> Self {
        Self {
            class,
            code,
            context: context.into(),
        }
    }

    pub(crate) fn semantic(code: &'static str, context: impl Into<String>) -> Self {
        Self::new(ErrorClass::Semantic, code, context)
    }

    pub(crate) fn resource(code: &'static str, context: impl Into<String>) -> Self {
        Self::new(ErrorClass::Resource, code, context)
    }

    pub fn code(&self) -> &str {
        self.code
    }
    pub fn class(&self) -> ErrorClass {
        self.class
    }
    pub fn context(&self) -> &str {
        &self.context
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.context)
    }
}

impl std::error::Error for Error {}
