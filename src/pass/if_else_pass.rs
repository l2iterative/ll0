use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::{ReadAddr, StructuredInstruction};

pub struct IfElsePass;

impl Pass for IfElsePass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let len = code.0.len();

        for cur in 0..len {
            match &code.0[cur].0 {
                StructuredInstruction::SELECT(w, rs, r1, r2) => {
                    if !matches!(r1, ReadAddr::Ref(_)) || !matches!(r2, ReadAddr::Ref(_)) {
                        continue;
                    }
                    let mut can_merge_len = 0;

                    let ws = *w;
                    let mut we = ws + 1;

                    let r1s = match r1 {
                        ReadAddr::Ref(s) => *s,
                        _ => unreachable!()
                    };
                    let mut r1e = r1s + 1;

                    let r2s = match r2 {
                        ReadAddr::Ref(s) => *s,
                        _ => unreachable!()
                    };
                    let mut r2e = r2s + 1;

                    let mut look = cur + 1;
                    loop {
                        if let StructuredInstruction::SELECT(look_w, look_rs, look_r1, look_r2) =
                            &code.0[look].0
                        {
                            if *look_w != we {
                                break;
                            }
                            if look_rs != rs {
                                break;
                            }
                            if !matches!(look_r1, ReadAddr::Ref(_))
                                || !matches!(look_r2, ReadAddr::Ref(_))
                            {
                                break;
                            }
                            let look_r1_v = match look_r1 {
                                ReadAddr::Ref(v) => *v,
                                _ => unreachable!()
                            };
                            let look_r2_v = match look_r2 {
                                ReadAddr::Ref(v) => *v,
                                _ => unreachable!()
                            };
                            if look_r1_v != r1e || look_r2_v != r2e {
                                break;
                            }

                            can_merge_len += 1;
                            we += 1;
                            r1e += 1;
                            r2e += 1;
                            look += 1;
                            continue;
                        } else {
                            break;
                        }
                    }

                    if can_merge_len > 1 {
                        code.0[cur].0 = StructuredInstruction::__SELECT_RANGE__(ws, we, rs.clone(), r1s, r1e, r2s, r2e);
                        for i in cur + 1..look {
                            code.0[i].0 = StructuredInstruction::__DELETE__;
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
