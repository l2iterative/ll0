use std::fmt::{Debug, Display, Formatter};
#[derive(Debug, Clone)]
pub enum ParserError {
    IllegalInstruction(Vec<u32>),
}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserError::IllegalInstruction(line) => {
                f.write_fmt(format_args!("Unknown instruction: {:?}", line))
            }
        }
    }
}
