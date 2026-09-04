use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl Severity {
    fn prefix(self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
            Severity::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub check: String,
    pub detail: String,
}

impl Finding {
    pub fn new(severity: Severity, check: impl Into<String>, detail: impl Into<String>) -> Self {
        Finding { severity, check: check.into(), detail: detail.into() }
    }

    pub fn pass(check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Pass, check, detail)
    }

    pub fn warn(check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Warn, check, detail)
    }

    pub fn fail(check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Fail, check, detail)
    }

    pub fn skip(check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(Severity::Skip, check, detail)
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<4} {}: {}", self.severity.prefix(), self.check, self.detail)
    }
}
