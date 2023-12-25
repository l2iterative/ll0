use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::{ReadAddr, ReadEndAddr, ReadStartAddr, StructuredInstruction, WriteAddr};
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
            ReadAddr::Ref(v) | ReadAddr::RefSub(v, _) => {
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
                | StructuredInstruction::SHA_LOAD(r) => {
                    v(r);
                }

                StructuredInstruction::SET_GLOBAL(r1, r2, r3, r4, _) => {
                    v(r1);
                    v(r2);
                    v(r3);
                    v(r4);
                }

                |StructuredInstruction::__SHA_FINI__(w) |
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
                )
                | StructuredInstruction::POSEIDON_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8)
                | StructuredInstruction::POSEIDON_ADD_LOAD_FROM_MONTGOMERY(
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
                | StructuredInstruction::POSEIDON_STORE(_, w)
                | StructuredInstruction::__POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(_, w)
                |
                StructuredInstruction::__POSEIDON_PERMUTE_STORE__(_, w)
                => {
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
                StructuredInstruction::SHA_INIT_START
                |StructuredInstruction::SHA_INIT_PADDING
                |StructuredInstruction::SHA_MIX
                |StructuredInstruction::SHA_FINI_PADDING
               | StructuredInstruction::WOM_INIT
                |StructuredInstruction::WOM_FINI
                |StructuredInstruction::READ_IOP_HEADER(_, _)
                |StructuredInstruction::POSEIDON_FULL
                |StructuredInstruction::POSEIDON_PARTIAL
                |StructuredInstruction::__DELETE__
                |StructuredInstruction::__PANIC__
                |StructuredInstruction::__POSEIDON_PERMUTE__
                | StructuredInstruction::__SHA_INIT__
                |StructuredInstruction::__SHA_MIX_48__ => {}
                |StructuredInstruction::__SELECT_RANGE__(ws, we, rs, r1s, r1e, r2s, r2e) => {
                    for i in *ws..*we {
                        u(&i);
                    }
                    v(rs);
                    for i in *r1s..*r1e {
                        v(&ReadAddr::Ref(i));
                    }

                    for i in *r2s..*r2e {
                        v(&ReadAddr::Ref(i));
                    }
                }
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
            ReadAddr::RefSub(m, idx) => {
                if remap.borrow().contains_key(m) {
                    *r = ReadAddr::RefSub(*remap.borrow().get(m).unwrap(), *idx);
                }
            }
            _ => {}
        };

        let is_available = |r: &ReadAddr| match r {
            ReadAddr::Ref(m) | ReadAddr::RefSub(m, _) => {
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
            _ => false,
        };

        let remap_u = |w: &mut WriteAddr, r: &ReadAddr| match r {
            ReadAddr::Ref(m) => {
                remap.borrow_mut().insert(*w, *m);
                *w = *m;
            }
            _ => {}
        };

        let has_remap_rule = |rs: &ReadStartAddr, re: &ReadEndAddr |  {
            let mut has_remap_rule = false;
            for x in *rs..*re {
                if remap.borrow().contains_key(&x) {
                    has_remap_rule = true;
                }
            }
            has_remap_rule
        };

        let mut cur = 0;
        while cur < code.0.len() {
            *(line_number.borrow_mut()) = cur;
            let insn = &mut code.0[cur].0;
            let is_select_expanded = match insn {
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
                    false
                }
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r)
                | StructuredInstruction::SHA_LOAD(r) => {
                    remap_v(r);
                    false
                }
                StructuredInstruction::SET_GLOBAL(r1, r2, r3, r4, _) => {
                    remap_v(r1);
                    remap_v(r2);
                    remap_v(r3);
                    remap_v(r4);
                    false
                }
                StructuredInstruction::NOT(w, r) | StructuredInstruction::INV(w, r) => {
                    if is_available(r) {
                        remap_v(r);
                        remap_u(w, r);
                    } else {
                        remap_v(r);
                    }
                    false
                }
                StructuredInstruction::EQ(r1, r2) => {
                    remap_v(r1);
                    remap_v(r2);
                    false
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
                    false
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
                    false
                }
                StructuredInstruction::EXTRACT(_, r, _) => {
                    remap_v(r);
                    false
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
                )
                | StructuredInstruction::POSEIDON_LOAD(_, _, r1, r2, r3, r4, r5, r6, r7, r8)
                | StructuredInstruction::POSEIDON_ADD_LOAD_FROM_MONTGOMERY(
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
                    false
                }
                StructuredInstruction::__MOV__(w, r) => {
                    if is_available(r) {
                        remap_v(r);
                        remap_u(w, r);
                        *insn = StructuredInstruction::__DELETE__;
                    } else {
                        remap_v(r);
                    }
                    false
                }
                StructuredInstruction::SHA_INIT_START
                |StructuredInstruction::SHA_INIT_PADDING
                |StructuredInstruction::SHA_MIX
                | StructuredInstruction::SHA_FINI_START(_)
                |StructuredInstruction::SHA_FINI_PADDING
                |StructuredInstruction::WOM_INIT
                |StructuredInstruction::WOM_FINI
                |StructuredInstruction::CONST(_, _, _)
                |StructuredInstruction::READ_IOP_HEADER(_, _)
                |StructuredInstruction::READ_IOP_BODY(_)
                |StructuredInstruction::POSEIDON_FULL
                |StructuredInstruction::POSEIDON_PARTIAL
                |StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(_, _)
                |StructuredInstruction::POSEIDON_STORE(_, _)
                |StructuredInstruction::__DELETE__
                |StructuredInstruction::__PANIC__
                |StructuredInstruction::__READ_IOP_BODY_BATCH__(_, _)
               | StructuredInstruction::__SHA_MIX_48__
               | StructuredInstruction::__POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(_, _)
                |StructuredInstruction::__POSEIDON_PERMUTE_STORE__(_, _)
               | StructuredInstruction::__POSEIDON_PERMUTE__
               | StructuredInstruction::__SHA_INIT__
               | StructuredInstruction::__SHA_FINI__(_) => {}
                StructuredInstruction::__SELECT_RANGE__(ws, we, rs, r1s, r1e, r2s, r2e) => {
                    if has_remap_rule(r1s, r1e) || has_remap_rule(r2s, r2e) {

                    } else {
                        remap_v(rs);
                    }
                    false
                }
            };
        }

        Ok(())
    }
}
