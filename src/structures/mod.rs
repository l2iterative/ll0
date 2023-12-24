use crate::math::{Fp, Fp4};
use std::fmt::{Display, Formatter};
use std::format_args;

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
pub enum StructuredInstruction {
    // m[{}] = (m[{}].0 & m[{}].0)
    BIT_AND_ELEM(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].0 & m[{}].0 + (m[{}].1 & m[{}].1) << 16)
    BIT_AND_SHORTS(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].0 ^ m[{}].0, m[{}].1 ^ m[{}].1)
    BIT_XOR_SHORTS(WriteAddr, ReadAddr, ReadAddr),
    // sha_init_start()
    SHA_INIT_START,
    // sha_init_padding()
    SHA_INIT_PADDING,
    // sha_load_from_montgomery(m[{}].0)
    SHA_LOAD_FROM_MONTGOMERY(ReadAddr),
    // sha_load(m[{}].0 + m[{}].1 << 16)
    SHA_LOAD(ReadAddr),
    // sha_mix()
    SHA_MIX,
    // sha_fini_start(&mut m[{}..={}])
    SHA_FINI_START(WriteStartAddr),
    // sha_fini_padding()
    SHA_FINI_PADDING,
    // wom_init()
    WOM_INIT,
    // wom_fini()
    WOM_FINI,
    // set_global(({}, {}, {}, {}, {}, {}, {}, {}), {})
    SET_GLOBAL(ReadAddr, ReadAddr, ReadAddr, ReadAddr, Index),
    // m[{}] = ({}, {})
    CONST(WriteAddr, Parameter, Parameter),
    // m[{}] = m[{}] + m[{}]
    ADD(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = m[{}] - m[{}]
    SUB(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = m[{}] * m[{}]
    MUL(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (!m[{}].0)
    NOT(WriteAddr, ReadAddr),
    // m[{}] = 1 / m[{}]
    INV(WriteAddr, ReadAddr),
    // assert_eq!(m[{}], m[{}])
    EQ(ReadAddr, ReadAddr),
    // iop = read_iop(IOP_Header {{ count: {}, k_and_flip_flag: {}}})
    READ_IOP_HEADER(Parameter, Parameter),
    // m[{}] = iop.pop()
    READ_IOP_BODY(WriteAddr),
    // m[{}] = (({} * m[{}].0) << 64 + m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0)
    MIX_RNG_WITH_PERV(WriteAddr, Parameter, ReadAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0)
    MIX_RNG(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = if m[{}].0 { m[{}] } else { m[{}] }
    SELECT(WriteAddr, ReadAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].{})
    EXTRACT(WriteAddr, ReadAddr, Index),
    // poseidon.add_consts = {}; poseidon.state{} = to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_LOAD_FROM_MONTGOMERY(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.add_consts = {}; poseidon.state{} = (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_LOAD(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.add_consts = {}; poseidon.state{} += to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_ADD_LOAD_FROM_MONTGOMERY(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.add_consts = {}; poseidon.state{} += (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_ADD_LOAD(
        Parameter,
        Index,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // poseidon.full()
    POSEIDON_FULL,
    // poseidon.partial()
    POSEIDON_PARTIAL,
    // poseidon.store_state{}_montgomery(&mut m[{}..={}])
    POSEIDON_STORE_TO_MONTGOMERY(Index, WriteStartAddr),
    // poseidon.store_state{}(&mut m[{}..={}])
    POSEIDON_STORE(Index, WriteStartAddr),
    // //delete
    __DELETE__,
    // panic!()
    __PANIC__,
    // m[{}] = m[{}]
    __MOV__(WriteAddr, ReadAddr),
    // iop.write(m[{}..={}])
    __READ_IOP_BODY_BATCH__(WriteStartAddr, WriteEndAddr),
    // for _ in 0..48 { sha_mix(); }
    __SHA_MIX_48__,
    // poseidon.permute_and_store_state{}_montgomery(&mut m[{}..={}])
    __POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(Index, WriteStartAddr),
    // poseidon.permute_and_store_state{}(&mut m[{}..={}])
    __POSEIDON_PERMUTE_STORE__(Index, WriteStartAddr),
    // poseidon.permute()
    __POSEIDON_PERMUTE__,
    // sha_init()
    __SHA_INIT__,
    // sha_fini(&mut m[{}..={}])
    __SHA_FINI__(WriteStartAddr),
    // m[{}..={}] = if m[{}].0 { m[{}..={}] } else { m[{}..={}] }
    __SELECT_RANGE__(
        WriteStartAddr,
        WriteEndAddr,
        ReadAddr,
        ReadStartAddr,
        ReadEndAddr,
        ReadStartAddr,
        ReadEndAddr,
    ),
}

impl Display for StructuredInstruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StructuredInstruction::BIT_AND_ELEM(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = {} & {};", w, r1._0(), r2._0()))
            }
            StructuredInstruction::BIT_AND_SHORTS(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = {} & {} + ({} & {}) << 16;",
                    w, r1._0(), r2._0(), r1._1(), r2._1()))
            }
            StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = ({} ^ {}, {} ^ {});",
                                         w, r1._0(), r2._0(), r1._1(), r2._1()))
            }
            StructuredInstruction::SHA_INIT_START => {
                f.write_fmt(format_args!("sha_init_start();"))
            }
            StructuredInstruction::SHA_INIT_PADDING => {
                f.write_fmt(format_args!("sha_init_padding();"))
            }
            StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r) => {
                f.write_fmt(format_args!(
                    "sha_load_from_montgomery({});",
                    r._0()
                ))
            }
            StructuredInstruction::SHA_LOAD(r) => {
                f.write_fmt(format_args!(
                    "sha_load({} + {} << 16);",
                    r._0(), r._1()
                ))
            }
            StructuredInstruction::SHA_MIX => {
                f.write_fmt(format_args!("sha_mix();"))
            }
            StructuredInstruction::SHA_FINI_START(rs) => {
                f.write_fmt(format_args!(
                    "sha_fini_start(&mut m[{}..={}]);",
                    rs,
                    rs + 8 - 1
                ))
            }
            StructuredInstruction::SHA_FINI_PADDING => {
                f.write_fmt(format_args!("sha_fini_padding();"))
            }
            StructuredInstruction::WOM_INIT => {
                f.write_fmt(format_args!("wom_init();"))
            }
            StructuredInstruction::WOM_FINI => {
                f.write_fmt(format_args!("wom_fini();"))
            }
            StructuredInstruction::SET_GLOBAL(r1, r2, r3, r4, idx) => {
                f.write_fmt(format_args!(
                    "set_global(({}, {}, {}, {}, {}, {}, {}, {}), {});",
                    r1._0(), r1._1(), r2._0(), r2._1(), r3._0(), r3._1(), r4._0(), r4._1(), idx
                ))
            }
            StructuredInstruction::CONST(w, fp1, fp2) => {
                if *fp2 == 0 {
                    f.write_fmt(format_args!(
                        "m[{}] = {};",
                        w, fp1
                    ))
                } else {
                    f.write_fmt(format_args!(
                        "m[{}] = ({}, {});",
                        w, fp1, fp2
                    ))
                }
            }
            StructuredInstruction::ADD(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = {} + {};",w, r1,r2
                ))
            }
            StructuredInstruction::SUB(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = {} - {};",w, r1,r2
                ))
            }
            StructuredInstruction::MUL(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = {} * {};", w, r1, r2
                ))
            }
            StructuredInstruction::NOT(w, r) => {
                f.write_fmt(format_args!(
                    "m[{}] = !{};",
                    w, r._0()
                ))
            }
            StructuredInstruction::INV(w, r) => {
                f.write_fmt(format_args!(
                    "m[{}] = 1 / {};", w, r
                ))
            }
            StructuredInstruction::EQ(r1, r2) => {
                f.write_fmt(format_args!("assert_eq!({}, {});", r1, r2))
            }
            StructuredInstruction::READ_IOP_HEADER(p1, p2) => {
                f.write_fmt(format_args!(
                    "iop = read_iop(IOP_Header {{ count: {}, k_and_flip_flag: {}}});",
                    p1, p2
                ))
            }
            StructuredInstruction::READ_IOP_BODY(w) => {
                f.write_fmt(format_args!(
                    "m[{}] = iop.pop();",
                    w
                ))
            }
            StructuredInstruction::MIX_RNG_WITH_PERV(w, fp, prev, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = ({} * {}) << 64 + {} << 48 + {} << 32 + {} << 16 + {};",
                    w, fp, prev._0(), r1._1(), r1._0(), r2._1(), r2._0()
                ))
            }
            StructuredInstruction::MIX_RNG(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = {} << 48 + {} << 32 + {} << 16 + {};",
                    w, r1._1(), r1._0(), r2._1(), r2._0()
                ))
            }
            StructuredInstruction::SELECT(w, s, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = if {} {{ {} }} else {{ {} }};",
                    w, s._0(), r1, r2
                ))
            }
            StructuredInstruction::EXTRACT(w, r, idx) => {
                let sub = if *idx == 0 {
                    r._0()
                } else if *idx == 1 {
                    r._1()
                } else if *idx == 2 {
                    r._2()
                } else {
                    r._3()
                };
                f.write_fmt(format_args!(
                    "m[{}] = {};",
                    w, sub
                ))
            }
            StructuredInstruction::POSEIDON_LOAD_FROM_MONTGOMERY(_, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.state = [0u32; 24]; poseidon.state[{}..={}] = from_montgomery!({}, {}, {}, {}, {}, {}, {}, {});",
                                         idx * 8, idx * 8 + 8 - 1, r1._0(), r2._0(), r3._0(), r4._0(), r5._0(), r6._0(), r7._0(), r8._0()
                ))
            }
            StructuredInstruction::POSEIDON_LOAD(_, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.state = [0u32; 24]; poseidon.state[{}..={}] = ({}, {}, {}, {}, {}, {}, {}, {});",
                                         idx * 8, idx * 8 + 8 - 1, r1._0(), r2._0(), r3._0(), r4._0(), r5._0(), r6._0(), r7._0(), r8._0()
                ))
            }
            StructuredInstruction::POSEIDON_ADD_LOAD_FROM_MONTGOMERY(_, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.state[{}..={}] += from_montgomery!({}, {}, {}, {}, {}, {}, {}, {});",
                                         idx * 8, idx * 8 + 8 - 1, r1._0(), r2._0(), r3._0(), r4._0(), r5._0(), r6._0(), r7._0(), r8._0()
                ))
            }
            StructuredInstruction::POSEIDON_ADD_LOAD(_, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.state[{}..={}] += ({}, {}, {}, {}, {}, {}, {}, {});",
                                         idx * 8, idx * 8 + 8 - 1,  r1._0(), r2._0(), r3._0(), r4._0(), r5._0(), r6._0(), r7._0(), r8._0()
                ))
            }
            StructuredInstruction::POSEIDON_FULL => {
                f.write_fmt(format_args!("poseidon.full();"))
            }
            StructuredInstruction::POSEIDON_PARTIAL => {
                f.write_fmt(format_args!("poseidon.partial();"))
            }
            StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(idx, ws) => {
                f.write_fmt(format_args!(
                    "m[{}..={}] = to_montgomery!(poseidon.state[{}..={}]);",
                   ws, ws + 8 - 1, idx * 8, idx * 8 + 8 - 1
                ))
            }
            StructuredInstruction::POSEIDON_STORE(idx, ws) => {
                f.write_fmt(format_args!(
                    "m[{}..={}] = poseidon.state[{}..={}];",
                    ws, ws + 8 - 1, idx * 8, idx * 8 + 8 - 1
                ))
            }
            StructuredInstruction::__DELETE__ => {
                f.write_fmt(format_args!("// deleted"))
            }
            StructuredInstruction::__PANIC__ => {
                f.write_fmt(format_args!("panic!();"))
            }
            StructuredInstruction::__MOV__(w, r) => {
                f.write_fmt(format_args!(
                    "m[{}] = {};",
                    w, r
                ))
            }
            StructuredInstruction::__READ_IOP_BODY_BATCH__(ws, we) => {
                f.write_fmt(format_args!(
                    "iop.write(&mut m[{}..={}]);",
                    ws, we - 1
                ))
            }
            StructuredInstruction::__SHA_MIX_48__ => {
                f.write_str("for _ in 0..48 { sha_mix(); }")
            }
            StructuredInstruction::__POSEIDON_PERMUTE_STORE_TO_MONTGOMERY__(idx, ws) => {
                f.write_fmt(format_args!(
                    "poseidon.permute(); m[{}..={}] = to_montgomery!(poseidon.state[{}..={}]);",
                    ws, ws + 8 - 1, idx * 8, idx * 8 + 8 - 1
                ))
            }
            StructuredInstruction::__POSEIDON_PERMUTE_STORE__(idx, ws) => {
                f.write_fmt(format_args!(
                    "poseidon.permute(); m[{}..={}] = poseidon.state[{}..={}];",
                    ws, ws + 8 - 1, idx * 8, idx * 8 + 8 - 1
                ))
            }
            StructuredInstruction::__POSEIDON_PERMUTE__ => {
                f.write_str(
                    "poseidon.permute();"
                )
            }
            StructuredInstruction::__SHA_INIT__ => {
                f.write_str(
                    "sha_init();"
                )
            }
            StructuredInstruction::__SHA_FINI__(rs) => {
                f.write_fmt(format_args!(
                    "sha_fini(&mut m[{}..={}]);",
                    rs,
                    rs + 8 - 1
                ))
            }
            StructuredInstruction::__SELECT_RANGE__(
                ws, we, rc, r1s, r1e, r2s, r2e
            )
            => {
                f.write_fmt(
                    format_args!("m[{}..={}] = if {} {{ m[{}..={}] }} else {{ m[{}..={}] }}",
                    ws, we - 1, rc._0(), r1s, r1e - 1, r2s, r2e - 1)
                )
            }
        }
    }
}

pub type WriteAddr = u32;

#[derive(Clone, PartialEq, Eq)]
pub enum ReadAddr {
    Ref(u32),
    RefSub(u32, u32),
    Const(Fp4),
}

pub type ReadStartAddr = u32;
pub type ReadEndAddr = u32;

pub type WriteStartAddr = u32;
pub type WriteEndAddr = u32;
pub type Index = u32;
pub type Parameter = u32;

impl From<u32> for ReadAddr {
    fn from(value: u32) -> Self {
        Self::Ref(value)
    }
}

impl Display for ReadAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadAddr::Ref(v) => f.write_fmt(format_args!("m[{}]", v)),
            ReadAddr::Const(v) => {
                if v.1 == Fp::ZERO && v.2 == Fp::ZERO && v.3 == Fp::ZERO {
                    f.write_fmt(format_args!("{}", v.0))
                } else if v.2 == Fp::ZERO && v.3 == Fp::ZERO {
                    f.write_fmt(format_args!("({}, {})", v.0, v.1))
                } else {
                    f.write_fmt(format_args!("({}, {}, {}, {})", v.0, v.1, v.2, v.3))
                }
            }
            ReadAddr::RefSub(v, idx) => f.write_fmt(format_args!("m[{}].{}", v, idx)),
        }
    }
}

impl ReadAddr {
    pub fn _0(&self) -> ReadAddr {
        match self {
            ReadAddr::Ref(v) => ReadAddr::RefSub(*v, 0),
            ReadAddr::Const(v) => {
                ReadAddr::Const(Fp4::new(v.0.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO))
            }
            ReadAddr::RefSub(v, idx) => ReadAddr::RefSub(*v, *idx),
        }
    }

    pub fn _1(&self) -> ReadAddr {
        match self {
            ReadAddr::Ref(v) => ReadAddr::RefSub(*v, 1),
            ReadAddr::Const(v) => {
                ReadAddr::Const(Fp4::new(v.1.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO))
            }
            ReadAddr::RefSub(_, _) => ReadAddr::Const(Fp4::default()),
        }
    }
    pub fn _2(&self) -> ReadAddr {
        match self {
            ReadAddr::Ref(v) => ReadAddr::RefSub(*v, 2),
            ReadAddr::Const(v) => {
                ReadAddr::Const(Fp4::new(v.2.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO))
            }
            ReadAddr::RefSub(_, _) => ReadAddr::Const(Fp4::default()),
        }
    }
    pub fn _3(&self) -> ReadAddr {
        match self {
            ReadAddr::Ref(v) => ReadAddr::RefSub(*v, 3),
            ReadAddr::Const(v) => {
                ReadAddr::Const(Fp4::new(v.3.clone(), Fp::ZERO, Fp::ZERO, Fp::ZERO))
            }
            ReadAddr::RefSub(_, _) => ReadAddr::Const(Fp4::default()),
        }
    }
}
