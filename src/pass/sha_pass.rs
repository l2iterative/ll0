use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::StructuredInstruction;

pub struct ShaPass;

impl Pass for ShaPass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let len = code.0.len();
        let mut cur = 0;

        while cur < len {
            if code.0[cur].0 == StructuredInstruction::SHA_MIX {
                for i in 1..48 {
                    if code.0[cur + i].0 != StructuredInstruction::SHA_MIX {
                        cur += 1;
                        continue;
                    }
                }
                code.0[cur].0 = StructuredInstruction::__SHA_MIX_48__;
                for i in 1..48 {
                    code.0[cur + i].0 = StructuredInstruction::__DELETE__;
                }
            }

            if code.0[cur].0 == StructuredInstruction::SHA_INIT_START {
                for i in 1..=3 {
                    if code.0[cur + i].0 != StructuredInstruction::SHA_INIT_PADDING {
                        cur += 1;
                        continue;
                    }
                }
                code.0[cur].0 = StructuredInstruction::__SHA_INIT__;
                for i in 1..=3 {
                    code.0[cur + i].0 = StructuredInstruction::__DELETE__;
                }
            }

            cur += 1;
        }

        Ok(())
    }
}
