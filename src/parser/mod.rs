mod error;

use crate::parser::error::ParserError;
use crate::{
    MACRO_BIT_AND_ELEM, MACRO_BIT_OP_SHORTS, MACRO_OPERAND_0, MACRO_OPERAND_1, MACRO_OPERAND_2,
    MACRO_SET_GLOBAL, MACRO_SHA_FINI, MACRO_SHA_INIT, MACRO_SHA_LOAD, MACRO_SHA_MIX,
    MACRO_WOM_FINI, MACRO_WOM_INIT, MICRO_ADD, MICRO_CONST, MICRO_EQ, MICRO_EXTRACT, MICRO_INV,
    MICRO_MIX_RNG, MICRO_MUL, MICRO_READ_IOP_BODY, MICRO_READ_IOP_HEADER, MICRO_SELECT, MICRO_SUB,
    POSEIDON_DO_MONT, POSEIDON_LOAD_ADD_CONSTS, POSEIDON_LOAD_G1, POSEIDON_LOAD_G2,
    POSEIDON_LOAD_KEEP_STATE, SELECT_MACRO_OPS, SELECT_MICRO_OPS, SELECT_POSEIDON_FULL,
    SELECT_POSEIDON_LOAD, SELECT_POSEIDON_PARTIAL, SELECT_POSEIDON_STORE, WRITE_ADDR,
};
use std::fmt::{Display, Formatter};

pub type WriteAddr = u32;
pub type ReadAddr = u32;
pub type WriteStartAddr = u32;
pub type Index = u32;
pub type Parameter = u32;
pub type Fp = u32;

#[allow(non_camel_case_types)]
pub enum StructuredInstruction {
    // m[{}] = (m[{}].0 & m[{}].0)
    BIT_AND_ELEM(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].0 & m[{}].0 + (m[{}].1 & m[{}].1) << 16)
    BIT_AND_SHORTS(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].0 ^ m[{}].0, m[{}].1 ^ m[{}].1)
    BIT_XOR_SHORTS(WriteAddr, ReadAddr, ReadAddr),
    // sha_init()
    SHA_INIT,
    // sha_init_padding()
    SHA_INIT_PADDING,
    // sha_load_from_montgomery(m[{}].0)
    SHA_LOAD_FROM_MONTGOMERY(ReadAddr),
    // sha_load(m[{}].0 + m[{}].1 << 16)
    SHA_LOAD(ReadAddr),
    // sha_mix()
    SHA_MIX,
    // sha_fini(&mut m[{}..{}])
    SHA_FINI(WriteStartAddr),
    // sha_fini_padding()
    SHA_FINI_PADDING,
    // wom_init()
    WOM_INIT,
    // wom_fini()
    WOM_FINI,
    // set_global(m[{}], {})
    SET_GLOBAL(ReadAddr, Index),
    // m[{}] = ({}, {})
    CONST(ReadAddr, Fp, Fp),
    // m[{}] = m[{}] + m[{}]
    ADD(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = m[{}] - m[{}]
    SUB(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = m[{}] * m[{}]
    MUL(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (!m[{}].0)
    NOT(WriteAddr, ReadAddr),
    // m[{}] = 1 / m[{}]
    INV(WriteAddr, ReadAddr),
    // assert_eq!(m[{}], m[{}])
    EQ(ReadAddr, ReadAddr),
    // iop = read_iop(IOP_Header {{ count: {}, k_and_flip_flag: {}}})
    READ_IOP_HEADER(Parameter, Parameter),
    // m[{}] = iop.pop()
    READ_IOP_BODY(WriteAddr),
    // m[{}] = (({} * m[{}].0) << 64 + m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0)
    MIX_RNG_WITH_PERV(
        WriteAddr,
        Fp,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // m[{}] = (m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0)
    MIX_RNG(WriteAddr, ReadAddr, ReadAddr, ReadAddr, ReadAddr),
    // m[{}] = if m[{}].0 { m[{}] } else { m[{}] }
    SELECT(WriteAddr, ReadAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].{})
    EXTRACT(WriteAddr, ReadAddr, Index),
    // poseidon.add_consts = {}; poseidon.state{} = to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_LOAD_TO_MONTGOMERY(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.add_consts = {}; poseidon.state{} = (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_LOAD(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.add_consts = {}; poseidon.state{} += to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_ADD_LOAD_TO_MONTGOMERY(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.add_consts = {}; poseidon.state{} += (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_ADD_LOAD(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.full()
    POSEIDON_FULL,
    // poseidon.partial()
    POSEIDON_PARTIAL,
    // poseidon.write_state{}_montgomery(&mut m[{}..{}])
    POSEIDON_STORE_TO_MONTGOMERY(Index, WriteStartAddr),
    // poseidon.write_state{}(&mut m[{}..{}])
    POSEIDON_STORE(Index, WriteStartAddr),
}

impl Display for StructuredInstruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StructuredInstruction::BIT_AND_ELEM(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = m[{}].0 & m[{}].0", w, r1, r2))
            }
            StructuredInstruction::BIT_AND_SHORTS(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = m[{}].0 & m[{}].0 + (m[{}].1 & m[{}].1) << 16",
                    w, r1, r2, r1, r2))
            }
            StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = (m[{}].0 ^ m[{}].0, m[{}].1 ^ m[{}].1)",
                                         w, r1, r2, r1, r2))
            }
            StructuredInstruction::SHA_INIT => {
                f.write_fmt(format_args!("sha_init()"))
            }
            StructuredInstruction::SHA_INIT_PADDING => {
                f.write_fmt(format_args!("sha_init_padding()"))
            }
            StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r) => {
                f.write_fmt(format_args!(
                    "sha_load_from_montgomery(m[{}].0)",
                    r
                ))
            }
            StructuredInstruction::SHA_LOAD(r) => {
                f.write_fmt(format_args!(
                    "sha_load(m[{}].0 + m[{}].1 << 16)",
                    r, r
                ))
            }
            StructuredInstruction::SHA_MIX => {
                f.write_fmt(format_args!("sha_mix()"))
            }
            StructuredInstruction::SHA_FINI(rs) => {
                f.write_fmt(format_args!(
                    "sha_fini(&mut m[{}..{}])",
                    rs,
                    rs + 8
                ))
            }
            StructuredInstruction::SHA_FINI_PADDING => {
                f.write_fmt(format_args!("sha_fini_padding()"))
            }
            StructuredInstruction::WOM_INIT => {
                f.write_fmt(format_args!("wom_init()"))
            }
            StructuredInstruction::WOM_FINI => {
                f.write_fmt(format_args!("wom_fini()"))
            }
            StructuredInstruction::SET_GLOBAL(r, idx) => {
                f.write_fmt(format_args!(
                    "set_global(m[{}], {})",
                    r, idx
                ))
            }
            StructuredInstruction::CONST(w, fp1, fp2) => {
                if *fp2 == 0 {
                    f.write_fmt(format_args!(
                        "m[{}] = {}",
                        w, fp1
                    ))
                } else {
                    f.write_fmt(format_args!(
                        "m[{}] = ({}, {})",
                        w, fp1, fp2
                    ))
                }
            }
            StructuredInstruction::ADD(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}] + m[{}]",w, r1,r2
                ))
            }
            StructuredInstruction::SUB(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}] - m[{}]",w, r1,r2
                ))
            }
            StructuredInstruction::MUL(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}] * m[{}]", w, r1, r2
                ))
            }
            StructuredInstruction::NOT(w, r) => {
                f.write_fmt(format_args!(
                    "m[{}] = !m[{}].0",
                    w, r
                ))
            }
            StructuredInstruction::INV(w, r) => {
                f.write_fmt(format_args!(
                    "m[{}] = 1 / m[{}]", w, r
                ))
            }
            StructuredInstruction::EQ(r1, r2) => {
                f.write_fmt(format_args!("assert_eq!(m[{}], m[{}])", r1, r2))
            }
            StructuredInstruction::READ_IOP_HEADER(p1, p2) => {
                f.write_fmt(format_args!(
                    "iop = read_iop(IOP_Header {{ count: {}, k_and_flip_flag: {}}})",
                    p1, p2
                ))
            }
            StructuredInstruction::READ_IOP_BODY(w) => {
                f.write_fmt(format_args!(
                    "m[{}] = iop.pop()",
                    w
                ))
            }
            StructuredInstruction::MIX_RNG_WITH_PERV(w, fp, prev, r1, r2, r3, r4) => {
                f.write_fmt(format_args!("m[{}] = ({} * m[{}].0) << 64 + m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0",
                    w, fp, prev, r1, r2, r3, r4
                ))
            }
            StructuredInstruction::MIX_RNG(w, r1, r2, r3, r4) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0",
                    w, r1, r2, r3, r4
                ))
            }
            StructuredInstruction::SELECT(w, s, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = if m[{}].0 {{ m[{}] }} else {{ m[{}] }}",
                    w, s, r1, r2
                ))
            }
            StructuredInstruction::EXTRACT(w, r, idx) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}].{}",
                    w, r, idx
                ))
            }
            StructuredInstruction::POSEIDON_LOAD_TO_MONTGOMERY(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} = to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_LOAD(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} = (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_ADD_LOAD_TO_MONTGOMERY(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} += to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_ADD_LOAD(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} += (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_FULL => {
                f.write_fmt(format_args!("poseidon.full()"))
            }
            StructuredInstruction::POSEIDON_PARTIAL => {
                f.write_fmt(format_args!("poseidon.partial()"))
            }
            StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(idx, rs) => {
                f.write_fmt(format_args!(
                    "poseidon.write_state{}_montgomery(&mut m[{}..{}])",
                   idx, rs, rs + 8
                ))
            }
            StructuredInstruction::POSEIDON_STORE(idx, rs) => {
                f.write_fmt(format_args!(
                    "poseidon.write_state{}(&mut m[{}..{}])",
                    idx, rs, rs+8
                ))
            }
        }
    }
}

#[derive(Default)]
struct GlobalState {
    sha_init_pos: usize,
    sha_fini_pos: usize,
    line_no: usize,
}

fn walk_macro(
    global_state: &mut GlobalState,
    out: &mut Code,
    insn: &[u32],
) -> Result<(), ParserError> {
    if insn[MACRO_BIT_AND_ELEM] == 1 {
        out.push(
            StructuredInstruction::BIT_AND_ELEM(
                insn[WRITE_ADDR],
                insn[MACRO_OPERAND_0],
                insn[MACRO_OPERAND_1],
            ),
            global_state.line_no,
        );
    } else if insn[MACRO_BIT_OP_SHORTS] == 1 {
        if insn[MACRO_OPERAND_2] != 0 {
            out.push(
                StructuredInstruction::BIT_AND_SHORTS(
                    insn[WRITE_ADDR],
                    insn[MACRO_OPERAND_0],
                    insn[MACRO_OPERAND_1],
                ),
                global_state.line_no,
            );
        } else {
            out.push(
                StructuredInstruction::BIT_XOR_SHORTS(
                    insn[WRITE_ADDR],
                    insn[MACRO_OPERAND_0],
                    insn[MACRO_OPERAND_1],
                ),
                global_state.line_no,
            );
        }
    } else if insn[MACRO_SHA_INIT] == 1 {
        if global_state.sha_init_pos == 0 {
            out.push(StructuredInstruction::SHA_INIT, global_state.line_no);
        } else {
            out.push(
                StructuredInstruction::SHA_INIT_PADDING,
                global_state.line_no,
            );
        }
        global_state.sha_init_pos = (global_state.sha_init_pos + 1) % 4;
    } else if insn[MACRO_SHA_LOAD] == 1 {
        if insn[MACRO_OPERAND_2] == 0 {
            out.push(
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(insn[MACRO_OPERAND_0]),
                global_state.line_no,
            );
        } else {
            out.push(
                StructuredInstruction::SHA_LOAD(insn[MACRO_OPERAND_0]),
                global_state.line_no,
            );
        }
    } else if insn[MACRO_SHA_MIX] == 1 {
        out.push(StructuredInstruction::SHA_MIX, global_state.line_no);
    } else if insn[MACRO_SHA_FINI] == 1 {
        if global_state.sha_fini_pos == 0 {
            let out_addr = insn[MACRO_OPERAND_0] - 3;
            out.push(
                StructuredInstruction::SHA_FINI(out_addr),
                global_state.line_no,
            );
        } else {
            out.push(
                StructuredInstruction::SHA_FINI_PADDING,
                global_state.line_no,
            );
        }
        global_state.sha_fini_pos = (global_state.sha_fini_pos + 1) % 4;
    } else if insn[MACRO_WOM_INIT] == 1 {
        out.push(StructuredInstruction::WOM_INIT, global_state.line_no);
    } else if insn[MACRO_WOM_FINI] == 1 {
        out.push(StructuredInstruction::WOM_FINI, global_state.line_no);
    } else if insn[MACRO_SET_GLOBAL] == 1 {
        out.push(
            StructuredInstruction::SET_GLOBAL(insn[MACRO_OPERAND_0], insn[MACRO_OPERAND_1]),
            global_state.line_no,
        );
    } else {
        return Err(ParserError::IllegalInstruction(insn.to_vec()));
    }
    Ok(())
}

fn walk_micro(
    global_state: &mut GlobalState,
    out: &mut Code,
    insn: &[u32],
) -> Result<(), ParserError> {
    let group = [
        [insn[7], insn[8], insn[9], insn[10]],
        [insn[11], insn[12], insn[13], insn[14]],
        [insn[15], insn[16], insn[17], insn[18]],
    ];

    for (i, row) in group.iter().enumerate() {
        let write_addr = insn[WRITE_ADDR] + i as u32;
        if row[0] == MICRO_CONST {
            out.push(
                StructuredInstruction::CONST(write_addr, row[1], row[2]),
                global_state.line_no,
            );
        } else if row[0] == MICRO_ADD {
            out.push(
                StructuredInstruction::ADD(write_addr, row[1], row[2]),
                global_state.line_no,
            );
        } else if row[0] == MICRO_SUB {
            out.push(
                StructuredInstruction::SUB(write_addr, row[1], row[2]),
                global_state.line_no,
            );
        } else if row[0] == MICRO_MUL {
            out.push(
                StructuredInstruction::MUL(write_addr, row[1], row[2]),
                global_state.line_no,
            );
        } else if row[0] == MICRO_INV {
            if row[2] == 0 {
                out.push(
                    StructuredInstruction::NOT(write_addr, row[1]),
                    global_state.line_no,
                );
            } else {
                out.push(
                    StructuredInstruction::INV(write_addr, row[1]),
                    global_state.line_no,
                );
            }
        } else if row[0] == MICRO_EQ {
            out.push(
                StructuredInstruction::EQ(row[1], row[2]),
                global_state.line_no,
            );
        } else if row[0] == MICRO_READ_IOP_HEADER {
            out.push(
                StructuredInstruction::READ_IOP_HEADER(row[1], row[2]),
                global_state.line_no,
            );
        } else if row[0] == MICRO_READ_IOP_BODY {
            out.push(
                StructuredInstruction::READ_IOP_BODY(write_addr),
                global_state.line_no,
            );
        } else if row[0] == MICRO_MIX_RNG {
            if row[3] != 0 {
                out.push(
                    StructuredInstruction::MIX_RNG_WITH_PERV(
                        write_addr,
                        row[3],
                        write_addr - 1,
                        row[1],
                        row[1],
                        row[2],
                        row[2],
                    ),
                    global_state.line_no,
                );
            } else {
                out.push(
                    StructuredInstruction::MIX_RNG(write_addr, row[1], row[1], row[2], row[2]),
                    global_state.line_no,
                );
            }
        } else if row[0] == MICRO_SELECT {
            let if_false = row[2];
            let if_true = if row[3] >= 1006632960u32 {
                row[2] - (2013265921 - row[3])
            } else {
                row[2] + row[3]
            };
            out.push(
                StructuredInstruction::SELECT(write_addr, row[1], if_true, if_false),
                global_state.line_no,
            );
        } else if row[0] == MICRO_EXTRACT {
            out.push(
                StructuredInstruction::EXTRACT(write_addr, row[1], row[2] * 2 + row[3]),
                global_state.line_no,
            );
        } else {
            return Err(ParserError::IllegalInstruction(insn.to_vec()));
        }
    }
    Ok(())
}

pub type LineNo = usize;

#[derive(Default)]
pub struct Code(pub Vec<(StructuredInstruction, LineNo)>);

impl Code {
    pub fn push(&mut self, insn: StructuredInstruction, line_no: usize) {
        self.0.push((insn, line_no));
    }
}

impl TryFrom<&[u32]> for Code {
    type Error = ParserError;

    fn try_from(value: &[u32]) -> Result<Self, Self::Error> {
        let mut global_state = GlobalState::default();
        let mut out = Code::default();

        for (idx, insn) in value.chunks_exact(21).enumerate() {
            global_state.line_no = idx + 1;

            if insn[SELECT_MACRO_OPS] == 1 {
                walk_macro(&mut global_state, &mut out, insn)?;
            } else if insn[SELECT_MICRO_OPS] == 1 {
                walk_micro(&mut global_state, &mut out, insn)?;
            } else if insn[SELECT_POSEIDON_LOAD] == 1 {
                let group = insn[POSEIDON_LOAD_G1] + insn[POSEIDON_LOAD_G2] * 2;
                if insn[POSEIDON_LOAD_KEEP_STATE] != 1 {
                    if insn[POSEIDON_DO_MONT] != 0 {
                        out.push(
                            StructuredInstruction::POSEIDON_LOAD_TO_MONTGOMERY(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13],
                                insn[14],
                                insn[15],
                                insn[16],
                                insn[17],
                                insn[18],
                                insn[19],
                                insn[20],
                            ),
                            global_state.line_no,
                        );
                    } else {
                        out.push(
                            StructuredInstruction::POSEIDON_LOAD(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13],
                                insn[14],
                                insn[15],
                                insn[16],
                                insn[17],
                                insn[18],
                                insn[19],
                                insn[20],
                            ),
                            global_state.line_no,
                        );
                    }
                } else {
                    if insn[POSEIDON_DO_MONT] != 0 {
                        out.push(
                            StructuredInstruction::POSEIDON_ADD_LOAD_TO_MONTGOMERY(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13],
                                insn[14],
                                insn[15],
                                insn[16],
                                insn[17],
                                insn[18],
                                insn[19],
                                insn[20],
                            ),
                            global_state.line_no,
                        );
                    } else {
                        out.push(
                            StructuredInstruction::POSEIDON_ADD_LOAD(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13],
                                insn[14],
                                insn[15],
                                insn[16],
                                insn[17],
                                insn[18],
                                insn[19],
                                insn[20],
                            ),
                            global_state.line_no,
                        );
                    }
                }
            } else if insn[SELECT_POSEIDON_FULL] == 1 {
                out.push(StructuredInstruction::POSEIDON_FULL, global_state.line_no);
            } else if insn[SELECT_POSEIDON_PARTIAL] == 1 {
                out.push(
                    StructuredInstruction::POSEIDON_PARTIAL,
                    global_state.line_no,
                );
            } else if insn[SELECT_POSEIDON_STORE] == 1 {
                let group = insn[POSEIDON_LOAD_G1] + insn[POSEIDON_LOAD_G2] * 2;
                if insn[POSEIDON_DO_MONT] != 0 {
                    out.push(
                        StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(
                            group,
                            insn[WRITE_ADDR],
                        ),
                        global_state.line_no,
                    );
                } else {
                    out.push(
                        StructuredInstruction::POSEIDON_STORE(group, insn[WRITE_ADDR]),
                        global_state.line_no,
                    );
                }
            } else {
                return Err(ParserError::IllegalInstruction(insn.to_vec()));
            }
        }

        return Ok(out);
    }
}
