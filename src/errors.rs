#[derive(Debug)]
pub struct GenericError(pub String);

impl std::error::Error for GenericError {}

impl std::fmt::Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::GenericError;

    #[test]
    fn test_display_and_error_trait() {
        let e = GenericError("boom".into());
        assert_eq!(e.to_string(), "error: boom");
        let _: &dyn std::error::Error = &e;
    }
}
