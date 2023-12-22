pub mod const_pass;
pub mod live_variable_analysis;
pub mod merge_iop_pass;
pub mod poseidon_pass;
pub mod reorder_pass;
pub mod sha_pass;

use crate::parser::Code;
use anyhow::Result;

pub trait Pass {
    fn pass(code: &mut Code) -> Result<()>;
}
