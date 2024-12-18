#[derive(Debug)]
pub struct GenericError(pub String);

impl std::error::Error for GenericError {}

impl std::fmt::Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: {}", self.0)
    }
}
