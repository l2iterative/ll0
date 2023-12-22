mod error;

use crate::parser::error::ParserError;
use crate::structures::StructuredInstruction;
use crate::{
    MACRO_BIT_AND_ELEM, MACRO_BIT_OP_SHORTS, MACRO_OPERAND_0, MACRO_OPERAND_1, MACRO_OPERAND_2,
    MACRO_SET_GLOBAL, MACRO_SHA_FINI, MACRO_SHA_INIT, MACRO_SHA_LOAD, MACRO_SHA_MIX,
    MACRO_WOM_FINI, MACRO_WOM_INIT, MICRO_ADD, MICRO_CONST, MICRO_EQ, MICRO_EXTRACT, MICRO_INV,
    MICRO_MIX_RNG, MICRO_MUL, MICRO_READ_IOP_BODY, MICRO_READ_IOP_HEADER, MICRO_SELECT, MICRO_SUB,
    POSEIDON_DO_MONT, POSEIDON_LOAD_ADD_CONSTS, POSEIDON_LOAD_G1, POSEIDON_LOAD_G2,
    POSEIDON_LOAD_KEEP_STATE, SELECT_MACRO_OPS, SELECT_MICRO_OPS, SELECT_POSEIDON_FULL,
    SELECT_POSEIDON_LOAD, SELECT_POSEIDON_PARTIAL, SELECT_POSEIDON_STORE, WRITE_ADDR,
};

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
                insn[MACRO_OPERAND_0].into(),
                insn[MACRO_OPERAND_1].into(),
            ),
            global_state.line_no,
        );
    } else if insn[MACRO_BIT_OP_SHORTS] == 1 {
        if insn[MACRO_OPERAND_2] != 0 {
            out.push(
                StructuredInstruction::BIT_AND_SHORTS(
                    insn[WRITE_ADDR],
                    insn[MACRO_OPERAND_0].into(),
                    insn[MACRO_OPERAND_1].into(),
                ),
                global_state.line_no,
            );
        } else {
            out.push(
                StructuredInstruction::BIT_XOR_SHORTS(
                    insn[WRITE_ADDR],
                    insn[MACRO_OPERAND_0].into(),
                    insn[MACRO_OPERAND_1].into(),
                ),
                global_state.line_no,
            );
        }
    } else if insn[MACRO_SHA_INIT] == 1 {
        if global_state.sha_init_pos == 0 {
            out.push(StructuredInstruction::SHA_INIT_START, global_state.line_no);
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
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(insn[MACRO_OPERAND_0].into()),
                global_state.line_no,
            );
        } else {
            out.push(
                StructuredInstruction::SHA_LOAD(insn[MACRO_OPERAND_0].into()),
                global_state.line_no,
            );
        }
    } else if insn[MACRO_SHA_MIX] == 1 {
        out.push(StructuredInstruction::SHA_MIX, global_state.line_no);
    } else if insn[MACRO_SHA_FINI] == 1 {
        if global_state.sha_fini_pos == 0 {
            let out_addr = insn[MACRO_OPERAND_0] - 3;
            out.push(
                StructuredInstruction::SHA_FINI_START(out_addr),
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
            StructuredInstruction::SET_GLOBAL(
                insn[MACRO_OPERAND_0].into(),
                (insn[MACRO_OPERAND_0] + 1).into(),
                (insn[MACRO_OPERAND_0] + 2).into(),
                (insn[MACRO_OPERAND_0] + 3).into(),
                insn[MACRO_OPERAND_1],
            ),
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
                StructuredInstruction::ADD(write_addr, row[1].into(), row[2].into()),
                global_state.line_no,
            );
        } else if row[0] == MICRO_SUB {
            out.push(
                StructuredInstruction::SUB(write_addr, row[1].into(), row[2].into()),
                global_state.line_no,
            );
        } else if row[0] == MICRO_MUL {
            out.push(
                StructuredInstruction::MUL(write_addr, row[1].into(), row[2].into()),
                global_state.line_no,
            );
        } else if row[0] == MICRO_INV {
            if row[2] == 0 {
                out.push(
                    StructuredInstruction::NOT(write_addr, row[1].into()),
                    global_state.line_no,
                );
            } else {
                out.push(
                    StructuredInstruction::INV(write_addr, row[1].into()),
                    global_state.line_no,
                );
            }
        } else if row[0] == MICRO_EQ {
            out.push(
                StructuredInstruction::EQ(row[1].into(), row[2].into()),
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
                        (write_addr - 1).into(),
                        row[1].into(),
                        row[2].into(),
                    ),
                    global_state.line_no,
                );
            } else {
                out.push(
                    StructuredInstruction::MIX_RNG(write_addr, row[1].into(), row[2].into()),
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
                StructuredInstruction::SELECT(
                    write_addr,
                    row[1].into(),
                    if_true.into(),
                    if_false.into(),
                ),
                global_state.line_no,
            );
        } else if row[0] == MICRO_EXTRACT {
            out.push(
                StructuredInstruction::EXTRACT(write_addr, row[1].into(), row[2] * 2 + row[3]),
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
                            StructuredInstruction::POSEIDON_LOAD_FROM_MONTGOMERY(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13].into(),
                                insn[14].into(),
                                insn[15].into(),
                                insn[16].into(),
                                insn[17].into(),
                                insn[18].into(),
                                insn[19].into(),
                                insn[20].into(),
                            ),
                            global_state.line_no,
                        );
                    } else {
                        out.push(
                            StructuredInstruction::POSEIDON_LOAD(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13].into(),
                                insn[14].into(),
                                insn[15].into(),
                                insn[16].into(),
                                insn[17].into(),
                                insn[18].into(),
                                insn[19].into(),
                                insn[20].into(),
                            ),
                            global_state.line_no,
                        );
                    }
                } else {
                    if insn[POSEIDON_DO_MONT] != 0 {
                        out.push(
                            StructuredInstruction::POSEIDON_ADD_LOAD_FROM_MONTGOMERY(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13].into(),
                                insn[14].into(),
                                insn[15].into(),
                                insn[16].into(),
                                insn[17].into(),
                                insn[18].into(),
                                insn[19].into(),
                                insn[20].into(),
                            ),
                            global_state.line_no,
                        );
                    } else {
                        out.push(
                            StructuredInstruction::POSEIDON_ADD_LOAD(
                                insn[POSEIDON_LOAD_ADD_CONSTS],
                                group,
                                insn[13].into(),
                                insn[14].into(),
                                insn[15].into(),
                                insn[16].into(),
                                insn[17].into(),
                                insn[18].into(),
                                insn[19].into(),
                                insn[20].into(),
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
