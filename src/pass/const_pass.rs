use crate::math::{Fp, Fp4};
use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::{ReadAddr, StructuredInstruction};
use std::collections::HashMap;

pub struct ConstPass;

impl Pass for ConstPass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let mut mem = HashMap::<u32, Fp4>::new();
        mem.insert(0, Fp4::default());

        let refresh_and_get_constant = |mem: &HashMap<u32, Fp4>, r: &mut ReadAddr| match r {
            ReadAddr::Ref(x) => {
                if mem.contains_key(x) {
                    let val = (mem.get(x).unwrap()).clone();
                    *r = ReadAddr::Const(val.clone());
                    Some(val)
                } else {
                    None
                }
            }
            ReadAddr::Const(v) => Some(v.clone()),
        };

        for (insn, _) in code.0.iter_mut() {
            match insn {
                StructuredInstruction::BIT_AND_ELEM(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.insert(*w, Fp4::new(&d1.0 & &d2.0, Fp::ZERO, Fp::ZERO, Fp::ZERO));
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::BIT_AND_SHORTS(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.insert(
                            *w,
                            Fp4::new(
                                &(&d1.0 & &d2.0) + &((&d1.1 & &d2.1) << 16),
                                Fp::ZERO,
                                Fp::ZERO,
                                Fp::ZERO,
                            ),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.insert(
                            *w,
                            Fp4::new(&d1.0 ^ &d2.0, &d1.1 ^ &d2.1, Fp::ZERO, Fp::ZERO),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r) => {
                    refresh_and_get_constant(&mem, r);
                }
                StructuredInstruction::SHA_LOAD(r) => {
                    refresh_and_get_constant(&mem, r);
                }
                StructuredInstruction::SET_GLOBAL(r, _) => {
                    refresh_and_get_constant(&mem, r);
                }
                StructuredInstruction::CONST(w, v1, v2) => {
                    mem.insert(*w, Fp4::new(Fp(*v1), Fp(*v2), Fp::ZERO, Fp::ZERO));
                    *insn = StructuredInstruction::__DELETE__;
                }
                StructuredInstruction::ADD(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.insert(*w, &d1 + &d2);
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d1.is_some() && d1.unwrap() == Fp4::default() {
                        *insn = StructuredInstruction::__MOV__(*w, r2.clone());
                    } else if d2.is_some() && d2.unwrap() == Fp4::default() {
                        *insn = StructuredInstruction::__MOV__(*w, r1.clone());
                    }
                }
                StructuredInstruction::SUB(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.insert(*w, &d1 - &d2);
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d2.is_some() && d2.unwrap() == Fp4::default() {
                        *insn = StructuredInstruction::__MOV__(*w, r1.clone());
                    }
                }
                StructuredInstruction::MUL(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.insert(*w, &d1 * &d2);
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d1.is_some() && d1.unwrap() == Fp4::default() {
                        mem.insert(*w, Fp4::default());
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d2.is_some() && d2.unwrap() == Fp4::default() {
                        mem.insert(*w, Fp4::default());
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::NOT(w, r) => {
                    let d = refresh_and_get_constant(&mem, r);
                    if d.is_some() {
                        let d = d.unwrap();
                        if d.0 .0 == 0 {
                            mem.insert(*w, Fp4::new(Fp(1), Fp::ZERO, Fp::ZERO, Fp::ZERO));
                        } else {
                            mem.insert(*w, Fp4::new(Fp::ZERO, Fp::ZERO, Fp::ZERO, Fp::ZERO));
                        }
                    }
                }
                StructuredInstruction::INV(w, r) => {
                    let d = refresh_and_get_constant(&mem, r);
                    if d.is_some() {
                        let d = d.unwrap();
                        mem.insert(*w, d.inv());
                    }
                }
                StructuredInstruction::EQ(r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        if d1 == d2 {
                            *insn = StructuredInstruction::__DELETE__;
                        } else {
                            *insn = StructuredInstruction::__PANIC__;
                        }
                    }
                }
                StructuredInstruction::MIX_RNG_WITH_PERV(w, fp, prev, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    let d_prev = refresh_and_get_constant(&mem, prev);
                    if d1.is_some() && d2.is_some() && d_prev.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        let d_prev = d_prev.unwrap();

                        let mut val = Fp(*fp) * d_prev.1;
                        const SHIFT_WORD: Fp = Fp(1 << 16);
                        val = val * SHIFT_WORD + d1.1;
                        val = val * SHIFT_WORD + d1.0;
                        val = val * SHIFT_WORD + d2.1;
                        val = val * SHIFT_WORD + d2.0;

                        mem.insert(*w, Fp4::new(val, Fp::ZERO, Fp::ZERO, Fp::ZERO));
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::MIX_RNG(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();

                        const SHIFT_WORD: Fp = Fp(1 << 16);
                        let mut val = d1.1;
                        val = val * SHIFT_WORD + d1.0;
                        val = val * SHIFT_WORD + d2.1;
                        val = val * SHIFT_WORD + d2.0;

                        mem.insert(*w, Fp4::new(val, Fp::ZERO, Fp::ZERO, Fp::ZERO));
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::SELECT(w, s, r1, r2) => {
                    let s = refresh_and_get_constant(&mem, s);
                    let d1 = refresh_and_get_constant(&mem, r1);
                    let d2 = refresh_and_get_constant(&mem, r2);

                    if s.is_some() {
                        let s = s.unwrap();
                        if s.0 == Fp(1) {
                            if d1.is_some() {
                                mem.insert(*w, d1.unwrap());
                                *insn = StructuredInstruction::__DELETE__;
                            } else {
                                *insn = StructuredInstruction::__MOV__(*w, r1.clone());
                            }
                        } else {
                            if d2.is_some() {
                                mem.insert(*w, d2.unwrap());
                                *insn = StructuredInstruction::__DELETE__;
                            } else {
                                *insn = StructuredInstruction::__MOV__(*w, r2.clone());
                            }
                        }
                    }
                }
                StructuredInstruction::EXTRACT(w, r, idx) => {
                    let d = refresh_and_get_constant(&mem, r);
                    if d.is_some() {
                        let d = d.unwrap();
                        let sub = if *idx == 0 {
                            d.0
                        } else if *idx == 1 {
                            d.1
                        } else if *idx == 2 {
                            d.2
                        } else {
                            d.3
                        };
                        mem.insert(*w, Fp4::new(sub, Fp::ZERO, Fp::ZERO, Fp::ZERO));
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::POSEIDON_LOAD_TO_MONTGOMERY(
                    _,
                    _,
                    r1,
                    r2,
                    r3,
                    r4,
                    r5,
                    r6,
                    r7,
                    r8,
                ) => {
                    refresh_and_get_constant(&mem, r1);
                    refresh_and_get_constant(&mem, r2);
                    refresh_and_get_constant(&mem, r3);
                    refresh_and_get_constant(&mem, r4);
                    refresh_and_get_constant(&mem, r5);
                    refresh_and_get_constant(&mem, r6);
                    refresh_and_get_constant(&mem, r7);
                    refresh_and_get_constant(&mem, r8);
                }
                StructuredInstruction::POSEIDON_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8) => {
                    refresh_and_get_constant(&mem, r1);
                    refresh_and_get_constant(&mem, r2);
                    refresh_and_get_constant(&mem, r3);
                    refresh_and_get_constant(&mem, r4);
                    refresh_and_get_constant(&mem, r5);
                    refresh_and_get_constant(&mem, r6);
                    refresh_and_get_constant(&mem, r7);
                    refresh_and_get_constant(&mem, r8);
                }
                StructuredInstruction::POSEIDON_ADD_LOAD_TO_MONTGOMERY(
                    _,
                    _,
                    r1,
                    r2,
                    r3,
                    r4,
                    r5,
                    r6,
                    r7,
                    r8,
                ) => {
                    refresh_and_get_constant(&mem, r1);
                    refresh_and_get_constant(&mem, r2);
                    refresh_and_get_constant(&mem, r3);
                    refresh_and_get_constant(&mem, r4);
                    refresh_and_get_constant(&mem, r5);
                    refresh_and_get_constant(&mem, r6);
                    refresh_and_get_constant(&mem, r7);
                    refresh_and_get_constant(&mem, r8);
                }
                StructuredInstruction::POSEIDON_ADD_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8) => {
                    refresh_and_get_constant(&mem, r1);
                    refresh_and_get_constant(&mem, r2);
                    refresh_and_get_constant(&mem, r3);
                    refresh_and_get_constant(&mem, r4);
                    refresh_and_get_constant(&mem, r5);
                    refresh_and_get_constant(&mem, r6);
                    refresh_and_get_constant(&mem, r7);
                    refresh_and_get_constant(&mem, r8);
                }
                StructuredInstruction::__MOV__(w, r) => {
                    let d = refresh_and_get_constant(&mem, r);
                    if d.is_some() {
                        mem.insert(*w, d.unwrap());
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
