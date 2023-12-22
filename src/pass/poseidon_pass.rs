use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::StructuredInstruction;

pub struct PoseidonPass;

impl Pass for PoseidonPass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let len = code.0.len();
        let mut cur = 5;

        while cur < len {
            if code.0[cur - 5].0 == StructuredInstruction::POSEIDON_FULL
                && code.0[cur - 4].0 == StructuredInstruction::POSEIDON_FULL
                && code.0[cur - 3].0 == StructuredInstruction::POSEIDON_PARTIAL
                && code.0[cur - 2].0 == StructuredInstruction::POSEIDON_FULL
                && code.0[cur - 1].0 == StructuredInstruction::POSEIDON_FULL
            {
                match code.0[cur].0 {
                    StructuredInstruction::POSEIDON_STORE(idx, ws) => {
                        code.0[cur].0 = StructuredInstruction::__POSEIDON_PERMUTE_STORE__(idx, ws);
                        for i in 1..=5 {
                            code.0[cur - i].0 = StructuredInstruction::__DELETE__;
                        }
                    }
                    StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(idx, ws) => {
                        code.0[cur].0 =
                            StructuredInstruction::__POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(
                                idx, ws,
                            );
                        for i in 1..=5 {
                            code.0[cur - i].0 = StructuredInstruction::__DELETE__;
                        }
                    }
                    _ => {
                        code.0[cur - 1].0 = StructuredInstruction::__POSEIDON_PERMUTE__;
                        for i in 2..=5 {
                            code.0[cur - i].0 = StructuredInstruction::__DELETE__;
                        }
                    }
                }
            }
            cur += 1;
        }

        Ok(())
    }
}
