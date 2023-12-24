use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::{ReadAddr, StructuredInstruction};

pub struct IfElsePass;

impl Pass for IfElsePass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let len = code.0.len();

        for cur in 0..len {
            match &code.0[cur] {
                StructuredInstruction::SELECT(w, rs, r1, r2) => {
                    if !matches!(r1, ReadAddr::Ref(_)) || !matches!(r2, ReadAddr::Ref(_)) {
                        continue;
                    }
                    let can_merge_len = 0;

                    let ws = *w;
                    let we = ws + 1;

                    let r1s = match r1 {
                        ReadAddr::Ref(s) => *s,
                        _ => {}
                    };
                    let r1e = r1s + 1;

                    let r2s = match r2 {
                        ReadAddr::Ref(s) => *s,
                        _ => {}
                    };
                    let r2e = r2s + 1;

                    let look = cur + 1;
                    loop {
                        if let StructuredInstruction::SELECT(look_w, look_rs, look_r1, look_r2) =
                            &code.0[look]
                        {
                            if look_w != we {
                                continue;
                            }
                            if look_rs != rs {
                                continue;
                            }
                            if !matches!(look_r1, ReadAddr::Ref(_))
                                || !matches!(look_r2, ReadAddr::Ref(_))
                            {
                                continue;
                            }
                            let look_r1_v = match look_r1 {
                                ReadAddr::Ref(v) => *v,
                                _ => {}
                            };
                            let look_r2_v = match look_r2 {
                                ReadAddr::Ref(v) => *v,
                                _ => {}
                            };
                            if look_r1_v != r1e || look_r2_v != r2e {
                                continue;
                            }
                        } else {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
