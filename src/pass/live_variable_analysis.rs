use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::{ReadAddr, StructuredInstruction, WriteAddr};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub struct LiveVariableAnalysisPass;

impl Pass for LiveVariableAnalysisPass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let last_use = Rc::new(RefCell::new(HashMap::<u32, usize>::new()));
        let line_number = Rc::new(RefCell::new(0usize));

        let u = |v: &WriteAddr| {
            last_use.borrow_mut().insert(*v, *line_number.borrow());
        };
        let v = |v: &ReadAddr| match v {
            ReadAddr::Ref(v) => {
                last_use.borrow_mut().insert(*v, *line_number.borrow());
            }
            ReadAddr::Const(_) => {}
        };

        for (i, (insn, _)) in code.0.iter().enumerate() {
            *(line_number.borrow_mut()) = i;
            match insn {
                StructuredInstruction::BIT_AND_ELEM(w, r1, r2)
                | StructuredInstruction::BIT_AND_SHORTS(w, r1, r2)
                | StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2)
                | StructuredInstruction::ADD(w, r1, r2)
                | StructuredInstruction::SUB(w, r1, r2)
                | StructuredInstruction::MUL(w, r1, r2)
                | StructuredInstruction::MIX_RNG(w, r1, r2) => {
                    u(w);
                    v(r1);
                    v(r2);
                }
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r)
                | StructuredInstruction::SHA_LOAD(r)
                | StructuredInstruction::SET_GLOBAL(r, _) => {
                    v(r);
                }
                StructuredInstruction::SHA_FINI_START(w) => {
                    u(w);
                    u(&(w + 1));
                    u(&(w + 2));
                    u(&(w + 3));
                    u(&(w + 4));
                    u(&(w + 5));
                    u(&(w + 6));
                    u(&(w + 7));
                }
                StructuredInstruction::CONST(w, _, _) | StructuredInstruction::READ_IOP_BODY(w) => {
                    u(w);
                }
                StructuredInstruction::NOT(w, r) | StructuredInstruction::INV(w, r) => {
                    u(w);
                    v(r);
                }
                StructuredInstruction::EQ(r1, r2) => {
                    v(r1);
                    v(r2);
                }
                StructuredInstruction::MIX_RNG_WITH_PERV(w, _, r_p, r1, r2) => {
                    u(w);
                    v(r_p);
                    v(r1);
                    v(r2);
                }
                StructuredInstruction::SELECT(w, s, r1, r2) => {
                    u(w);
                    v(s);
                    v(r1);
                    v(r2);
                }
                StructuredInstruction::EXTRACT(w, r, _) => {
                    u(w);
                    v(r);
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
                )
                | StructuredInstruction::POSEIDON_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8)
                | StructuredInstruction::POSEIDON_ADD_LOAD_TO_MONTGOMERY(
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
                )
                | StructuredInstruction::POSEIDON_ADD_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8) => {
                    v(r1);
                    v(r2);
                    v(r3);
                    v(r4);
                    v(r5);
                    v(r6);
                    v(r7);
                    v(r8);
                }
                StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(_, w)
                | StructuredInstruction::POSEIDON_STORE(_, w) => {
                    u(w);
                    u(&(w + 1));
                    u(&(w + 2));
                    u(&(w + 3));
                    u(&(w + 4));
                    u(&(w + 5));
                    u(&(w + 6));
                    u(&(w + 7));
                }
                StructuredInstruction::__MOV__(w, r) => {
                    u(w);
                    v(r);
                }
                StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, we) => {
                    for i in *ws..*we {
                        u(&i);
                    }
                }
                _ => {}
            }
        }

        *(line_number.borrow_mut()) = 0;

        let remap = Rc::new(RefCell::new(HashMap::<u32, u32>::new()));

        let remap_v = |r: &mut ReadAddr| match r {
            ReadAddr::Ref(m) => {
                if remap.borrow().contains_key(m) {
                    *r = ReadAddr::Ref(*remap.borrow().get(m).unwrap());
                }
            }
            _ => {}
        };

        let is_available = |r: &ReadAddr| match r {
            ReadAddr::Ref(m) => {
                if let Some(v) = last_use.borrow().get(m) {
                    if *v == *(line_number.borrow()) {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            ReadAddr::Const(_) => false,
        };

        let remap_u = |w: &mut WriteAddr, r: &ReadAddr| match r {
            ReadAddr::Ref(m) => {
                remap.borrow_mut().insert(*w, *m);
                *w = *m;
            }
            _ => {}
        };

        for (i, (insn, _)) in code.0.iter_mut().enumerate() {
            *(line_number.borrow_mut()) = i;
            match insn {
                StructuredInstruction::BIT_AND_ELEM(w, r1, r2)
                | StructuredInstruction::BIT_AND_SHORTS(w, r1, r2)
                | StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2)
                | StructuredInstruction::ADD(w, r1, r2)
                | StructuredInstruction::SUB(w, r1, r2)
                | StructuredInstruction::MUL(w, r1, r2)
                | StructuredInstruction::MIX_RNG(w, r1, r2) => {
                    if is_available(r1) {
                        remap_v(r1);
                        remap_v(r2);
                        remap_u(w, r1);
                    } else if is_available(r2) {
                        remap_v(r1);
                        remap_v(r2);
                        remap_u(w, r2);
                    } else {
                        remap_v(r1);
                        remap_v(r2);
                    }
                }
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r)
                | StructuredInstruction::SHA_LOAD(r)
                | StructuredInstruction::SET_GLOBAL(r, _) => {
                    remap_v(r);
                }
                StructuredInstruction::NOT(w, r) | StructuredInstruction::INV(w, r) => {
                    if is_available(r) {
                        remap_v(r);
                        remap_u(w, r);
                    } else {
                        remap_v(r);
                    }
                }
                StructuredInstruction::EQ(r1, r2) => {
                    remap_v(r1);
                    remap_v(r2);
                }
                StructuredInstruction::MIX_RNG_WITH_PERV(w, _, r_p, r1, r2) => {
                    if is_available(r_p) {
                        remap_v(r_p);
                        remap_u(w, r_p);
                        remap_v(r1);
                        remap_v(r2);
                    } else if is_available(r1) {
                        remap_v(r_p);
                        remap_v(r1);
                        remap_u(w, r1);
                        remap_v(r2);
                    } else if is_available(r2) {
                        remap_v(r_p);
                        remap_v(r1);
                        remap_v(r2);
                        remap_u(w, r2);
                    } else {
                        remap_v(r_p);
                        remap_v(r1);
                        remap_v(r2);
                    }
                }
                StructuredInstruction::SELECT(w, s, r1, r2) => {
                    if is_available(r1) {
                        remap_v(s);
                        remap_v(r1);
                        remap_u(w, r1);
                        remap_v(r2);
                    } else if is_available(r2) {
                        remap_v(s);
                        remap_v(r1);
                        remap_v(r2);
                        remap_u(w, r2);
                    } else {
                        remap_v(s);
                        remap_v(r1);
                        remap_v(r2);
                    }
                }
                StructuredInstruction::EXTRACT(_, r, _) => {
                    remap_v(r);
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
                )
                | StructuredInstruction::POSEIDON_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8)
                | StructuredInstruction::POSEIDON_ADD_LOAD_TO_MONTGOMERY(
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
                )
                | StructuredInstruction::POSEIDON_ADD_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8) => {
                    remap_v(r1);
                    remap_v(r2);
                    remap_v(r3);
                    remap_v(r4);
                    remap_v(r5);
                    remap_v(r6);
                    remap_v(r7);
                    remap_v(r8);
                }
                StructuredInstruction::__MOV__(w, r) => {
                    if is_available(r) {
                        remap_v(r);
                        remap_u(w, r);
                        *insn = StructuredInstruction::__DELETE__;
                    } else {
                        remap_v(r);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
