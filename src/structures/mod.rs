use crate::parser::{Fp, Index, Parameter, ReadAddr, WriteAddr, WriteStartAddr};
use std::fmt::{Display, Formatter};
use std::format_args;

#[allow(non_camel_case_types)]
pub enum StructuredInstruction {
    // m[{}] = (m[{}].0 & m[{}].0)
    BIT_AND_ELEM(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].0 & m[{}].0 + (m[{}].1 & m[{}].1) << 16)
    BIT_AND_SHORTS(WriteAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].0 ^ m[{}].0, m[{}].1 ^ m[{}].1)
    BIT_XOR_SHORTS(WriteAddr, ReadAddr, ReadAddr),
    // sha_init()
    SHA_INIT,
    // sha_init_padding()
    SHA_INIT_PADDING,
    // sha_load_from_montgomery(m[{}].0)
    SHA_LOAD_FROM_MONTGOMERY(ReadAddr),
    // sha_load(m[{}].0 + m[{}].1 << 16)
    SHA_LOAD(ReadAddr),
    // sha_mix()
    SHA_MIX,
    // sha_fini(&mut m[{}..{}])
    SHA_FINI(WriteStartAddr),
    // sha_fini_padding()
    SHA_FINI_PADDING,
    // wom_init()
    WOM_INIT,
    // wom_fini()
    WOM_FINI,
    // set_global(m[{}], {})
    SET_GLOBAL(ReadAddr, Index),
    // m[{}] = ({}, {})
    CONST(ReadAddr, Fp, Fp),
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
    MIX_RNG_WITH_PERV(
        WriteAddr,
        Fp,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
        ReadAddr,
    ),
    // m[{}] = (m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0)
    MIX_RNG(WriteAddr, ReadAddr, ReadAddr, ReadAddr, ReadAddr),
    // m[{}] = if m[{}].0 { m[{}] } else { m[{}] }
    SELECT(WriteAddr, ReadAddr, ReadAddr, ReadAddr),
    // m[{}] = (m[{}].{})
    EXTRACT(WriteAddr, ReadAddr, Index),
    // poseidon.add_consts = {}; poseidon.state{} = to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)
    POSEIDON_LOAD_TO_MONTGOMERY(
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
    POSEIDON_ADD_LOAD_TO_MONTGOMERY(
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
    // poseidon.write_state{}_montgomery(&mut m[{}..{}])
    POSEIDON_STORE_TO_MONTGOMERY(Index, WriteStartAddr),
    // poseidon.write_state{}(&mut m[{}..{}])
    POSEIDON_STORE(Index, WriteStartAddr),
}

impl Display for StructuredInstruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StructuredInstruction::BIT_AND_ELEM(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = m[{}].0 & m[{}].0", w, r1, r2))
            }
            StructuredInstruction::BIT_AND_SHORTS(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = m[{}].0 & m[{}].0 + (m[{}].1 & m[{}].1) << 16",
                    w, r1, r2, r1, r2))
            }
            StructuredInstruction::BIT_XOR_SHORTS(w, r1, r2) => {
                f.write_fmt(format_args!("m[{}] = (m[{}].0 ^ m[{}].0, m[{}].1 ^ m[{}].1)",
                                         w, r1, r2, r1, r2))
            }
            StructuredInstruction::SHA_INIT => {
                f.write_fmt(format_args!("sha_init()"))
            }
            StructuredInstruction::SHA_INIT_PADDING => {
                f.write_fmt(format_args!("sha_init_padding()"))
            }
            StructuredInstruction::SHA_LOAD_FROM_MONTGOMERY(r) => {
                f.write_fmt(format_args!(
                    "sha_load_from_montgomery(m[{}].0)",
                    r
                ))
            }
            StructuredInstruction::SHA_LOAD(r) => {
                f.write_fmt(format_args!(
                    "sha_load(m[{}].0 + m[{}].1 << 16)",
                    r, r
                ))
            }
            StructuredInstruction::SHA_MIX => {
                f.write_fmt(format_args!("sha_mix()"))
            }
            StructuredInstruction::SHA_FINI(rs) => {
                f.write_fmt(format_args!(
                    "sha_fini(&mut m[{}..{}])",
                    rs,
                    rs + 8
                ))
            }
            StructuredInstruction::SHA_FINI_PADDING => {
                f.write_fmt(format_args!("sha_fini_padding()"))
            }
            StructuredInstruction::WOM_INIT => {
                f.write_fmt(format_args!("wom_init()"))
            }
            StructuredInstruction::WOM_FINI => {
                f.write_fmt(format_args!("wom_fini()"))
            }
            StructuredInstruction::SET_GLOBAL(r, idx) => {
                f.write_fmt(format_args!(
                    "set_global(m[{}], {})",
                    r, idx
                ))
            }
            StructuredInstruction::CONST(w, fp1, fp2) => {
                if *fp2 == 0 {
                    f.write_fmt(format_args!(
                        "m[{}] = {}",
                        w, fp1
                    ))
                } else {
                    f.write_fmt(format_args!(
                        "m[{}] = ({}, {})",
                        w, fp1, fp2
                    ))
                }
            }
            StructuredInstruction::ADD(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}] + m[{}]",w, r1,r2
                ))
            }
            StructuredInstruction::SUB(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}] - m[{}]",w, r1,r2
                ))
            }
            StructuredInstruction::MUL(w, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}] * m[{}]", w, r1, r2
                ))
            }
            StructuredInstruction::NOT(w, r) => {
                f.write_fmt(format_args!(
                    "m[{}] = !m[{}].0",
                    w, r
                ))
            }
            StructuredInstruction::INV(w, r) => {
                f.write_fmt(format_args!(
                    "m[{}] = 1 / m[{}]", w, r
                ))
            }
            StructuredInstruction::EQ(r1, r2) => {
                f.write_fmt(format_args!("assert_eq!(m[{}], m[{}])", r1, r2))
            }
            StructuredInstruction::READ_IOP_HEADER(p1, p2) => {
                f.write_fmt(format_args!(
                    "iop = read_iop(IOP_Header {{ count: {}, k_and_flip_flag: {}}})",
                    p1, p2
                ))
            }
            StructuredInstruction::READ_IOP_BODY(w) => {
                f.write_fmt(format_args!(
                    "m[{}] = iop.pop()",
                    w
                ))
            }
            StructuredInstruction::MIX_RNG_WITH_PERV(w, fp, prev, r1, r2, r3, r4) => {
                f.write_fmt(format_args!("m[{}] = ({} * m[{}].0) << 64 + m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0",
                    w, fp, prev, r1, r2, r3, r4
                ))
            }
            StructuredInstruction::MIX_RNG(w, r1, r2, r3, r4) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0",
                    w, r1, r2, r3, r4
                ))
            }
            StructuredInstruction::SELECT(w, s, r1, r2) => {
                f.write_fmt(format_args!(
                    "m[{}] = if m[{}].0 {{ m[{}] }} else {{ m[{}] }}",
                    w, s, r1, r2
                ))
            }
            StructuredInstruction::EXTRACT(w, r, idx) => {
                f.write_fmt(format_args!(
                    "m[{}] = m[{}].{}",
                    w, r, idx
                ))
            }
            StructuredInstruction::POSEIDON_LOAD_TO_MONTGOMERY(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} = to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_LOAD(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} = (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_ADD_LOAD_TO_MONTGOMERY(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} += to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_ADD_LOAD(p, idx, r1, r2, r3, r4, r5, r6, r7, r8) => {
                f.write_fmt(format_args!("poseidon.add_consts = {}; poseidon.state{} += (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)",
                                         p, idx, r1, r2, r3, r4, r5, r6, r7, r8
                ))
            }
            StructuredInstruction::POSEIDON_FULL => {
                f.write_fmt(format_args!("poseidon.full()"))
            }
            StructuredInstruction::POSEIDON_PARTIAL => {
                f.write_fmt(format_args!("poseidon.partial()"))
            }
            StructuredInstruction::POSEIDON_STORE_TO_MONTGOMERY(idx, rs) => {
                f.write_fmt(format_args!(
                    "poseidon.write_state{}_montgomery(&mut m[{}..{}])",
                   idx, rs, rs + 8
                ))
            }
            StructuredInstruction::POSEIDON_STORE(idx, rs) => {
                f.write_fmt(format_args!(
                    "poseidon.write_state{}(&mut m[{}..{}])",
                    idx, rs, rs+8
                ))
            }
        }
    }
}
