use crate::parser::Code;
use crate::pass::Pass;
use crate::structures::{ReadAddr, ReadEndAddr, ReadStartAddr, StructuredInstruction, WriteAddr};
use anyhow::bail;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::AddAssign;
use std::rc::Rc;

pub struct ReorderPass;

impl Pass for ReorderPass {
    fn pass(code: &mut Code) -> anyhow::Result<()> {
        let next_id = Rc::new(RefCell::new(1u32));
        let remap = Rc::new(RefCell::new(HashMap::new()));

        let add_u = |w: &WriteAddr| {
            if !remap.borrow().contains_key(w) {
                let id = *next_id.borrow();
                remap.borrow_mut().insert(*w, id);
                next_id.borrow_mut().add_assign(1u32);
            }
        };

        for (insn, _) in code.0.iter() {
            match insn {
                StructuredInstruction::BIT_AND_ELEM(w, _, _)
                | StructuredInstruction::BIT_AND_SHORTS(w, _, _)
                | StructuredInstruction::BIT_XOR_SHORTS(w, _, _)
                | StructuredInstruction::CONST(w, _, _)
                | StructuredInstruction::ADD(w, _, _)
                | StructuredInstruction::SUB(w, _, _)
                | StructuredInstruction::MUL(w, _, _)
                | StructuredInstruction::NOT(w, _)
                | StructuredInstruction::INV(w, _)
                | StructuredInstruction::READ_IOP_BODY(w)
                | StructuredInstruction::MIX_RNG_WITH_PERV(w, _, _, _, _)
                | StructuredInstruction::MIX_RNG(w, _, _)
                | StructuredInstruction::SELECT(w, _, _, _)
                | StructuredInstruction::__MOV__(w, _)
                | StructuredInstruction::EXTRACT(w, _, _) => {
                    add_u(w);
                }
                StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, we) => {
                    for i in *ws..*we {
                        add_u(&i);
                    }
                }
                StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(_, ws)
                | StructuredInstruction::POSEIDON_STORE(_, ws)
                | StructuredInstruction::__POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(_, ws)
                | StructuredInstruction::__POSEIDON_PERMUTE_STORE__(_, ws)
                | StructuredInstruction::__SHA_FINI__(ws)
                | StructuredInstruction::SHA_FINI_START(ws) => {
                    for i in *ws..*ws + 8 {
                        add_u(&i);
                    }
                }
                StructuredInstruction::__SELECT_RANGE__(ws, we, rs, r1s, r1e, r2s, r2e) => {
                    for i in *ws..*we {
                        add_u(&i);
                    }
                }
                _ => {}
            }
        }

        let remap_v = |r: &mut ReadAddr| match r {
            ReadAddr::Ref(m) => {
                if remap.borrow().contains_key(m) {
                    *r = ReadAddr::Ref(*remap.borrow().get(m).unwrap());
                    Ok(())
                } else {
                    bail!("read a variable that has not been written before");
                }
            }
            ReadAddr::RefSub(m, idx) => {
                if remap.borrow().contains_key(m) {
                    *r = ReadAddr::RefSub(*remap.borrow().get(m).unwrap(), *idx);
                    Ok(())
                } else {
                    bail!("read a variable that has not been written before");
                }
            }
            ReadAddr::Const(_) => Ok(()),
        };

        let reorder_together = |rs: &mut ReadStartAddr, re: &mut ReadEndAddr| {
            let len = re - rs;
            let mut new_positions: Vec<Option<u32>> = vec![None; len];
            for i in rs..re {}
        };

        let remap_u = |w: &mut WriteAddr| {
            if remap.borrow().contains_key(w) {
                *w = *remap.borrow().get(w).unwrap();
                Ok(())
            } else {
                bail!("read a variable that has not been written before");
            }
        };

        for (insn, _) in code.0.iter_mut() {
            match insn {
                StructuredInstruction::BIT_AND_ELEM(w, r1, r2)
                | StructuredInstruction::BIT_AND_SHORTS(w, r1, r2)
                | StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2)
                | StructuredInstruction::ADD(w, r1, r2)
                | StructuredInstruction::SUB(w, r1, r2)
                | StructuredInstruction::MUL(w, r1, r2)
                | StructuredInstruction::MIX_RNG(w, r1, r2) => {
                    remap_v(r1)?;
                    remap_v(r2)?;
                    remap_u(w)?;
                }
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r)
                | StructuredInstruction::SHA_LOAD(r) => {
                    remap_v(r)?;
                }
                StructuredInstruction::SET_GLOBAL(r1, r2, r3, r4, _) => {
                    remap_v(r1)?;
                    remap_v(r2)?;
                    remap_v(r3)?;
                    remap_v(r4)?;
                }
                StructuredInstruction::NOT(w, r) | StructuredInstruction::INV(w, r) => {
                    remap_v(r)?;
                    remap_u(w)?;
                }
                StructuredInstruction::EQ(r1, r2) => {
                    remap_v(r1)?;
                    remap_v(r2)?;
                }
                StructuredInstruction::MIX_RNG_WITH_PERV(w, _, r_p, r1, r2) => {
                    remap_v(r_p)?;
                    remap_u(w)?;
                    remap_v(r1)?;
                    remap_v(r2)?;
                }
                StructuredInstruction::SELECT(w, s, r1, r2) => {
                    remap_v(s)?;
                    remap_v(r1)?;
                    remap_u(w)?;
                    remap_v(r2)?;
                }
                StructuredInstruction::EXTRACT(_, r, _) => {
                    remap_v(r)?;
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
                    remap_v(r1)?;
                    remap_v(r2)?;
                    remap_v(r3)?;
                    remap_v(r4)?;
                    remap_v(r5)?;
                    remap_v(r6)?;
                    remap_v(r7)?;
                    remap_v(r8)?;
                }
                StructuredInstruction::__MOV__(w, r) => {
                    remap_v(r)?;
                    remap_u(w)?;
                }
                StructuredInstruction::SHA_FINI_START(ws) => {
                    remap_u(ws)?;
                }
                StructuredInstruction::CONST(w, _, _) => {
                    remap_u(w)?;
                }
                StructuredInstruction::READ_IOP_BODY(w) => {
                    remap_u(w)?;
                }
                StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(_, ws)
                | StructuredInstruction::POSEIDON_STORE(_, ws)
                | StructuredInstruction::__POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(_, ws)
                | StructuredInstruction::__SHA_FINI__(ws)
                | StructuredInstruction::__POSEIDON_PERMUTE_STORE__(_, ws) => {
                    remap_u(ws)?;
                }
                StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, we) => {
                    remap_u(ws)?;
                    let mut new_we = *we - 1;
                    remap_u(&mut new_we)?;
                    *we = new_we + 1;
                }

                StructuredInstruction::SHA_FINI_PADDING
                | StructuredInstruction::WOM_INIT
                | StructuredInstruction::WOM_FINI
                | StructuredInstruction::READ_IOP_HEADER(_, _)
                | StructuredInstruction::POSEIDON_FULL
                | StructuredInstruction::POSEIDON_PARTIAL
                | StructuredInstruction::__DELETE__
                | StructuredInstruction::__PANIC__
                | StructuredInstruction::__SHA_MIX_48__
                | StructuredInstruction::__POSEIDON_PERMUTE__
                | StructuredInstruction::__SHA_INIT__
                | StructuredInstruction::SHA_INIT_START
                | StructuredInstruction::SHA_INIT_PADDING
                | StructuredInstruction::SHA_MIX => {}
            }
        }

        Ok(())
    }
}
