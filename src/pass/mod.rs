pub mod const_pass;
pub mod merge_iop_pass;

use crate::parser::Code;
use anyhow::Result;

pub trait Pass {
    fn pass(&mut self, code: &mut Code) -> Result<()>;
}
