pub mod parser;

pub const SELECT_MACRO_OPS: usize = 2;
pub const SELECT_MICRO_OPS: usize = 1;
pub const SELECT_POSEIDON_FULL: usize = 4;
pub const SELECT_POSEIDON_LOAD: usize = 3;
pub const SELECT_POSEIDON_PARTIAL: usize = 5;
pub const SELECT_POSEIDON_STORE: usize = 6;

pub const WRITE_ADDR: usize = 0;

pub const MACRO_BIT_AND_ELEM: usize = 10;
pub const MACRO_BIT_OP_SHORTS: usize = 11;
pub const MACRO_NOP: usize = 7;
pub const MACRO_SET_GLOBAL: usize = 16;
pub const MACRO_SHA_FINI: usize = 13;
pub const MACRO_SHA_INIT: usize = 12;
pub const MACRO_SHA_LOAD: usize = 14;
pub const MACRO_SHA_MIX: usize = 15;
pub const MACRO_WOM_FINI: usize = 9;
pub const MACRO_WOM_INIT: usize = 8;

pub const MACRO_OPERAND_0: usize = 17;
pub const MACRO_OPERAND_1: usize = 18;
pub const MACRO_OPERAND_2: usize = 19;

pub const MICRO_CONST: u32 = 0;
pub const MICRO_ADD: u32 = 1;
pub const MICRO_SUB: u32 = 2;
pub const MICRO_MUL: u32 = 3;
pub const MICRO_INV: u32 = 4;
pub const MICRO_EQ: u32 = 5;
pub const MICRO_READ_IOP_HEADER: u32 = 6;
pub const MICRO_READ_IOP_BODY: u32 = 7;
pub const MICRO_MIX_RNG: u32 = 8;
pub const MICRO_SELECT: u32 = 9;
pub const MICRO_EXTRACT: u32 = 10;

pub const POSEIDON_LOAD_ADD_CONSTS: usize = 9;
pub const POSEIDON_DO_MONT: usize = 7;
pub const POSEIDON_LOAD_KEEP_STATE: usize = 8;
pub const POSEIDON_LOAD_G0: usize = 10;
pub const POSEIDON_LOAD_G1: usize = 11;
pub const POSEIDON_LOAD_G2: usize = 12;
