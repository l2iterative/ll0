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
                StructuredInstruction::__SELECT_RANGE__(ws, we, _, _, _, _, _) => {
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

        let can_reorder_together = |rs: &ReadStartAddr, re: &ReadEndAddr| {
            let mut has_missing = false;
            for i in *rs..*re {
                if !remap.borrow().contains_key(&i) {
                    has_missing = true;
                }
            }
            !has_missing
        };

        let reorder_together = |rs: &mut ReadStartAddr, re: &mut ReadEndAddr| {
            *rs = *remap.borrow().get(rs).unwrap();
            *re = (*remap.borrow().get(&((*re) - 1)).unwrap()) + 1;
        };

        let remap_u = |w: &mut WriteAddr| {
            if remap.borrow().contains_key(w) {
                *w = *remap.borrow().get(w).unwrap();
                Ok(())
            } else {
                bail!("read a variable that has not been written before");
            }
        };

        let mut cur = 0;
        while cur < code.0.len() {
            let is_select_expanded = match &mut code.0[cur].0 {
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
                    false
                }
                StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r)
                | StructuredInstruction::SHA_LOAD(r) => {
                    remap_v(r)?;
                    false
                }
                StructuredInstruction::SET_GLOBAL(r1, r2, r3, r4, _) => {
                    remap_v(r1)?;
                    remap_v(r2)?;
                    remap_v(r3)?;
                    remap_v(r4)?;
                    false
                }
                StructuredInstruction::NOT(w, r) | StructuredInstruction::INV(w, r) => {
                    remap_v(r)?;
                    remap_u(w)?;
                    false
                }
                StructuredInstruction::EQ(r1, r2) => {
                    remap_v(r1)?;
                    remap_v(r2)?;
                    false
                }
                StructuredInstruction::MIX_RNG_WITH_PERV(w, _, r_p, r1, r2) => {
                    remap_v(r_p)?;
                    remap_u(w)?;
                    remap_v(r1)?;
                    remap_v(r2)?;
                    false
                }
                StructuredInstruction::SELECT(w, s, r1, r2) => {
                    remap_v(s)?;
                    remap_v(r1)?;
                    remap_u(w)?;
                    remap_v(r2)?;
                    false
                }
                StructuredInstruction::EXTRACT(_, r, _) => {
                    remap_v(r)?;
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
                    remap_v(r1)?;
                    remap_v(r2)?;
                    remap_v(r3)?;
                    remap_v(r4)?;
                    remap_v(r5)?;
                    remap_v(r6)?;
                    remap_v(r7)?;
                    remap_v(r8)?;
                    false
                }
                StructuredInstruction::__MOV__(w, r) => {
                    remap_v(r)?;
                    remap_u(w)?;
                    false
                }
                StructuredInstruction::SHA_FINI_START(ws) => {
                    remap_u(ws)?;
                    false
                }
                StructuredInstruction::CONST(w, _, _) => {
                    remap_u(w)?;
                    false
                }
                StructuredInstruction::READ_IOP_BODY(w) => {
                    remap_u(w)?;
                    false
                }
                StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(_, ws)
                | StructuredInstruction::POSEIDON_STORE(_, ws)
                | StructuredInstruction::__POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(_, ws)
                | StructuredInstruction::__SHA_FINI__(ws)
                | StructuredInstruction::__POSEIDON_PERMUTE_STORE__(_, ws) => {
                    remap_u(ws)?;
                    false
                }
                StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, we) => {
                    remap_u(ws)?;
                    let mut new_we = *we - 1;
                    remap_u(&mut new_we)?;
                    *we = new_we + 1;
                    false
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
                | StructuredInstruction::SHA_MIX => {
                    false
                }
                StructuredInstruction::__SELECT_RANGE__(ws, we, rs, r1s, r1e, r2s, r2e) => {
                    // try to remap as much as possible first
                    let can_remap_r1 = can_reorder_together(r1s, r1e);
                    let can_remap_r2 = can_reorder_together(r2s, r2e);
                    let can_remap_w = can_reorder_together(ws, we);

                    if !can_remap_r1 || !can_remap_r2 || !can_remap_w {
                        // expand the __SELECT_RANGE__ back to line-by-line SELECT
                        true
                    } else {
                        remap_v(rs)?;
                        reorder_together(r1s, r1e);
                        reorder_together(r2s, r2e);
                        reorder_together(ws, we);

                        false
                    }
                }
            };

            if is_select_expanded {
                if let StructuredInstruction::__SELECT_RANGE__(ws, we, rs, r1s, _, r2s, _) = code.0[cur].0.clone() {
                    for i in 0..we - ws {
                        let mut tbd_w = ws + i;
                        let mut tbd_r1 = ReadAddr::Ref(r1s + i);
                        let mut tbd_r2 = ReadAddr::Ref(r2s + i);

                        remap_u(&mut tbd_w)?;
                        remap_v(&mut tbd_r1)?;
                        remap_v(&mut tbd_r2)?;

                        code.0[cur + i as usize].0 = StructuredInstruction::SELECT(tbd_w, rs.clone(), tbd_r1, tbd_r2);
                    }
                    cur += (we - ws) as usize;
                }
            } else {
                cur += 1;
            }
        }

        Ok(())
    }
}
