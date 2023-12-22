use crate::math::{Fp, Fp4};
use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::{ReadAddr, StructuredInstruction};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

#[derive(Clone)]
pub enum RedirectionEntry {
    Const(Fp4),
    RefSub(u32, u32),
}

pub struct ConstPass;

impl Pass for ConstPass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let mem = Rc::new(RefCell::new(HashMap::<u32, RedirectionEntry>::new()));
        mem.borrow_mut()
            .insert(0, RedirectionEntry::Const(Fp4::default()));

        let refresh_and_get_constant = |r: &mut ReadAddr| match r {
            ReadAddr::Ref(x) => {
                if mem.borrow().contains_key(x) {
                    let m = mem.borrow().get(x).unwrap().clone();
                    match m {
                        RedirectionEntry::Const(val) => {
                            *r = ReadAddr::Const(val.clone());
                            Some(val.clone())
                        }
                        RedirectionEntry::RefSub(val, idx) => {
                            *r = ReadAddr::RefSub(val, idx);
                            None
                        }
                    }
                } else {
                    None
                }
            }
            ReadAddr::RefSub(x, idx) => {
                if mem.borrow().contains_key(x) {
                    let m = (mem.borrow().get(x).unwrap()).clone();
                    match m {
                        RedirectionEntry::Const(val) => {
                            let new_val = if *idx == 0 {
                                Fp4::new(val.0.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO)
                            } else if *idx == 1 {
                                Fp4::new(val.1.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO)
                            } else if *idx == 2 {
                                Fp4::new(val.2.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO)
                            } else {
                                Fp4::new(val.3.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO)
                            };

                            *r = ReadAddr::Const(new_val);
                            Some(val.clone())
                        }
                        RedirectionEntry::RefSub(val, val_idx) => {
                            if *idx == 0 {
                                *r = ReadAddr::RefSub(val, val_idx);
                                None
                            } else {
                                *r = ReadAddr::Const(Fp4::default());
                                Some(Fp4::default())
                            }
                        }
                    }
                } else {
                    None
                }
            }
            ReadAddr::Const(v) => Some(v.clone()),
        };

        for (insn, _) in code.0.iter_mut() {
            match insn {
                StructuredInstruction::BIT_AND_ELEM(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.borrow_mut().insert(
                            *w,
                            RedirectionEntry::Const(Fp4::new(
                                &d1.0 & &d2.0,
                                Fp::ZERO,
                                Fp::ZERO,
                                Fp::ZERO,
                            )),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::BIT_AND_SHORTS(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.borrow_mut().insert(
                            *w,
                            RedirectionEntry::Const(Fp4::new(
                                &(&d1.0 & &d2.0) + &((&d1.1 & &d2.1) << 16),
                                Fp::ZERO,
                                Fp::ZERO,
                                Fp::ZERO,
                            )),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.borrow_mut().insert(
                            *w,
                            RedirectionEntry::Const(Fp4::new(
                                &d1.0 ^ &d2.0,
                                &d1.1 ^ &d2.1,
                                Fp::ZERO,
                                Fp::ZERO,
                            )),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r) => {
                    refresh_and_get_constant(r);
                }
                StructuredInstruction::SHA_LOAD(r) => {
                    refresh_and_get_constant(r);
                }
                StructuredInstruction::SET_GLOBAL(r1, r2, r3, r4, _) => {
                    refresh_and_get_constant(r1);
                    refresh_and_get_constant(r2);
                    refresh_and_get_constant(r3);
                    refresh_and_get_constant(r4);
                }
                StructuredInstruction::CONST(w, v1, v2) => {
                    mem.borrow_mut().insert(
                        *w,
                        RedirectionEntry::Const(Fp4::new(Fp(*v1), Fp(*v2), Fp::ZERO, Fp::ZERO)),
                    );
                    *insn = StructuredInstruction::__DELETE__;
                }
                StructuredInstruction::ADD(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.borrow_mut()
                            .insert(*w, RedirectionEntry::Const(&d1 + &d2));
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d1.is_some() && d1.unwrap() == Fp4::default() {
                        *insn = StructuredInstruction::__MOV__(*w, r2.clone());
                    } else if d2.is_some() && d2.unwrap() == Fp4::default() {
                        *insn = StructuredInstruction::__MOV__(*w, r1.clone());
                    }
                }
                StructuredInstruction::SUB(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.borrow_mut()
                            .insert(*w, RedirectionEntry::Const(&d1 - &d2));
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d2.is_some() && d2.unwrap() == Fp4::default() {
                        *insn = StructuredInstruction::__MOV__(*w, r1.clone());
                    }
                }
                StructuredInstruction::MUL(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();
                        mem.borrow_mut()
                            .insert(*w, RedirectionEntry::Const(&d1 * &d2));
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d1.is_some() && d1.unwrap() == Fp4::default() {
                        mem.borrow_mut()
                            .insert(*w, RedirectionEntry::Const(Fp4::default()));
                        *insn = StructuredInstruction::__DELETE__;
                    } else if d2.is_some() && d2.unwrap() == Fp4::default() {
                        mem.borrow_mut()
                            .insert(*w, RedirectionEntry::Const(Fp4::default()));
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::NOT(w, r) => {
                    let d = refresh_and_get_constant(r);
                    if d.is_some() {
                        let d = d.unwrap();
                        if d.0 .0 == 0 {
                            mem.borrow_mut().insert(
                                *w,
                                RedirectionEntry::Const(Fp4::new(
                                    Fp(1),
                                    Fp::ZERO,
                                    Fp::ZERO,
                                    Fp::ZERO,
                                )),
                            );
                        } else {
                            mem.borrow_mut().insert(
                                *w,
                                RedirectionEntry::Const(Fp4::new(
                                    Fp::ZERO,
                                    Fp::ZERO,
                                    Fp::ZERO,
                                    Fp::ZERO,
                                )),
                            );
                        }
                    }
                }
                StructuredInstruction::INV(w, r) => {
                    let d = refresh_and_get_constant(r);
                    if d.is_some() {
                        let d = d.unwrap();
                        mem.borrow_mut()
                            .insert(*w, RedirectionEntry::Const(d.inv()));
                    }
                }
                StructuredInstruction::EQ(r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
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
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    let d_prev = refresh_and_get_constant(prev);
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

                        mem.borrow_mut().insert(
                            *w,
                            RedirectionEntry::Const(Fp4::new(val, Fp::ZERO, Fp::ZERO, Fp::ZERO)),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::MIX_RNG(w, r1, r2) => {
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);
                    if d1.is_some() && d2.is_some() {
                        let d1 = d1.unwrap();
                        let d2 = d2.unwrap();

                        const SHIFT_WORD: Fp = Fp(1 << 16);
                        let mut val = d1.1;
                        val = val * SHIFT_WORD + d1.0;
                        val = val * SHIFT_WORD + d2.1;
                        val = val * SHIFT_WORD + d2.0;

                        mem.borrow_mut().insert(
                            *w,
                            RedirectionEntry::Const(Fp4::new(val, Fp::ZERO, Fp::ZERO, Fp::ZERO)),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                StructuredInstruction::SELECT(w, s, r1, r2) => {
                    let s = refresh_and_get_constant(s);
                    let d1 = refresh_and_get_constant(r1);
                    let d2 = refresh_and_get_constant(r2);

                    if s.is_some() {
                        let s = s.unwrap();
                        if s.0 == Fp(1) {
                            if d1.is_some() {
                                mem.borrow_mut()
                                    .insert(*w, RedirectionEntry::Const(d1.unwrap()));
                                *insn = StructuredInstruction::__DELETE__;
                            } else {
                                *insn = StructuredInstruction::__MOV__(*w, r1.clone());
                            }
                        } else {
                            if d2.is_some() {
                                mem.borrow_mut()
                                    .insert(*w, RedirectionEntry::Const(d2.unwrap()));
                                *insn = StructuredInstruction::__DELETE__;
                            } else {
                                *insn = StructuredInstruction::__MOV__(*w, r2.clone());
                            }
                        }
                    }
                }
                StructuredInstruction::EXTRACT(w, r, idx) => {
                    let d = refresh_and_get_constant(r);
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
                        mem.borrow_mut().insert(
                            *w,
                            RedirectionEntry::Const(Fp4::new(sub, Fp::ZERO, Fp::ZERO, Fp::ZERO)),
                        );
                        *insn = StructuredInstruction::__DELETE__;
                    } else {
                        match r {
                            ReadAddr::Ref(v) => {
                                mem.borrow_mut()
                                    .insert(*w, RedirectionEntry::RefSub(*v, *idx));
                                *insn = StructuredInstruction::__DELETE__;
                            }
                            ReadAddr::RefSub(v, v_idx) => {
                                if *idx == 0 {
                                    mem.borrow_mut()
                                        .insert(*w, RedirectionEntry::RefSub(*v, *v_idx));
                                } else {
                                    mem.borrow_mut()
                                        .insert(*w, RedirectionEntry::Const(Fp4::default()));
                                }
                                *insn = StructuredInstruction::__DELETE__;
                            }
                            ReadAddr::Const(_) => {}
                        }
                    }
                }
                StructuredInstruction::POSEIDON_LOAD_FROM_MONTGOMERY(
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
                    refresh_and_get_constant(r1);
                    refresh_and_get_constant(r2);
                    refresh_and_get_constant(r3);
                    refresh_and_get_constant(r4);
                    refresh_and_get_constant(r5);
                    refresh_and_get_constant(r6);
                    refresh_and_get_constant(r7);
                    refresh_and_get_constant(r8);
                }
                StructuredInstruction::POSEIDON_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8) => {
                    refresh_and_get_constant(r1);
                    refresh_and_get_constant(r2);
                    refresh_and_get_constant(r3);
                    refresh_and_get_constant(r4);
                    refresh_and_get_constant(r5);
                    refresh_and_get_constant(r6);
                    refresh_and_get_constant(r7);
                    refresh_and_get_constant(r8);
                }
                StructuredInstruction::POSEIDON_ADD_LOAD_FROM_MONTGOMERY(
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
                    refresh_and_get_constant(r1);
                    refresh_and_get_constant(r2);
                    refresh_and_get_constant(r3);
                    refresh_and_get_constant(r4);
                    refresh_and_get_constant(r5);
                    refresh_and_get_constant(r6);
                    refresh_and_get_constant(r7);
                    refresh_and_get_constant(r8);
                }
                StructuredInstruction::POSEIDON_ADD_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8) => {
                    refresh_and_get_constant(r1);
                    refresh_and_get_constant(r2);
                    refresh_and_get_constant(r3);
                    refresh_and_get_constant(r4);
                    refresh_and_get_constant(r5);
                    refresh_and_get_constant(r6);
                    refresh_and_get_constant(r7);
                    refresh_and_get_constant(r8);
                }
                StructuredInstruction::__MOV__(w, r) => {
                    let d = refresh_and_get_constant(r);
                    if d.is_some() {
                        mem.borrow_mut()
                            .insert(*w, RedirectionEntry::Const(d.unwrap()));
                        *insn = StructuredInstruction::__DELETE__;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
