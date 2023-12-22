use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::StructuredInstruction;

pub struct MergeIOPPass;

impl Pass for MergeIOPPass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let len = code.0.len();
        let mut cur = 0;

        while cur < len {
            match code.0[cur].0 {
                StructuredInstruction::READ_IOP_BODY(w) => {
                    if cur != 0 {
                        match code.0[cur - 1].0 {
                            StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, we) => {
                                if w == we {
                                    code.0[cur - 1].0 = StructuredInstruction::__DELETE__;
                                    code.0[cur].0 =
                                        StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, we + 1);
                                }
                            }
                            StructuredInstruction::READ_IOP_BODY(ws) => {
                                if ws + 1 == w {
                                    code.0[cur - 1].0 = StructuredInstruction::__DELETE__;
                                    code.0[cur].0 =
                                        StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, ws + 2);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            cur += 1;
        }

        Ok(())
    }
}
