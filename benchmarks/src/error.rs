//! Error types for benchmark operations.

/// Errors that can occur during benchmark execution.
///
/// ```
/// use benchmarks::error::BenchmarkError;
///
/// let err = BenchmarkError::ToolNotFound("vegeta".into());
/// assert_eq!(err.to_string(), "tool not found: vegeta");
/// ```
#[derive(Debug, thiserror::Error)]
pub enum BenchmarkError {
    /// A required external tool is not installed.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// An external tool exited with a non-zero status.
    #[error("tool failed: {tool} exited with {code}")]
    ToolFailed {
        /// The tool that failed.
        tool: String,
        /// The exit code.
        code: i32,
        /// Stderr output.
        stderr: String,
    },

    /// Failed to parse tool output.
    #[error("failed to parse {tool} output: {reason}")]
    ParseError {
        /// The tool whose output could not be parsed.
        tool: String,
        /// What went wrong.
        reason: String,
    },

    /// I/O error during benchmark execution.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML serialization/deserialization error.
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_tool_not_found() {
        let err = BenchmarkError::ToolNotFound("vegeta".into());
        assert_eq!(
            err.to_string(),
            "tool not found: vegeta",
            "ToolNotFound display should include the tool name"
        );
    }

    #[test]
    fn display_tool_failed() {
        let err = BenchmarkError::ToolFailed {
            tool: "fortio".into(),
            code: 1,
            stderr: "something went wrong".into(),
        };
        assert_eq!(
            err.to_string(),
            "tool failed: fortio exited with 1",
            "ToolFailed display should include tool name and exit code"
        );
    }

    #[test]
    fn display_parse_error() {
        let err = BenchmarkError::ParseError {
            tool: "vegeta".into(),
            reason: "unexpected EOF".into(),
        };
        assert_eq!(
            err.to_string(),
            "failed to parse vegeta output: unexpected EOF",
            "ParseError display should include tool and reason"
        );
    }

    #[test]
    fn display_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = BenchmarkError::Io(io_err);
        assert_eq!(
            err.to_string(),
            "io error: file missing",
            "Io display should wrap the inner io error message"
        );
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let msg = json_err.to_string();
        let err = BenchmarkError::Json(json_err);
        assert_eq!(
            err.to_string(),
            format!("json error: {msg}"),
            "Json display should wrap the serde_json error"
        );
    }

    #[test]
    fn display_yaml_error() {
        let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(": : :").unwrap_err();
        let msg = yaml_err.to_string();
        let err = BenchmarkError::Yaml(yaml_err);
        assert_eq!(
            err.to_string(),
            format!("yaml error: {msg}"),
            "Yaml display should wrap the serde_yaml error"
        );
    }

    #[test]
    fn error_trait_source_for_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "disk full");
        let err = BenchmarkError::Io(io_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Io variant should have a source error");
    }

    #[test]
    fn error_trait_source_for_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = BenchmarkError::Json(json_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Json variant should have a source error");
    }
}
