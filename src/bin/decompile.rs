use clap::Parser;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use lowlevel0::*;

#[derive(Parser, Debug)]
#[command(about = "Decompile a ZKR file", long_about = None)]
struct Args {
    // Filename of the ZKR file to be unzipped
    #[arg(short, long, required = true)]
    file: String,

    // Output file, default to [filename].ll0
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Default)]
struct GlobalState {
    sha_init_pos: usize,
    sha_fini_pos: usize,
    line_no: usize,
}

fn walk_macro<W: Write>(global_state: &mut GlobalState, w: &mut W, insn: &[u32]) {
    w.write_fmt(format_args!("{}: ", global_state.line_no))
        .unwrap();
    if insn[MACRO_BIT_AND_ELEM] == 1 {
        w.write_fmt(format_args!(
            "m[{}] = (m[{}].0 & m[{}].0)\n",
            insn[WRITE_ADDR], insn[MACRO_OPERAND_0], insn[MACRO_OPERAND_1]
        ))
        .unwrap();
    } else if insn[MACRO_BIT_OP_SHORTS] == 1 {
        if insn[MACRO_OPERAND_2] != 0 {
            w.write_fmt(format_args!(
                "m[{}] = (m[{}].0 & m[{}].0 + (m[{}].1 & m[{}].1) << 16)\n",
                insn[WRITE_ADDR],
                insn[MACRO_OPERAND_0],
                insn[MACRO_OPERAND_1],
                insn[MACRO_OPERAND_0],
                insn[MACRO_OPERAND_1],
            ))
            .unwrap();
        } else {
            w.write_fmt(format_args!(
                "m[{}] = (m[{}].0 ^ m[{}].0, m[{}].1 ^ m[{}].1)\n",
                insn[WRITE_ADDR],
                insn[MACRO_OPERAND_0],
                insn[MACRO_OPERAND_1],
                insn[MACRO_OPERAND_0],
                insn[MACRO_OPERAND_1],
            ))
            .unwrap();
        }
    } else if insn[MACRO_SHA_INIT] == 1 {
        if global_state.sha_init_pos == 0 {
            w.write_fmt(format_args!("sha_init()\n")).unwrap();
        } else {
            w.write_fmt(format_args!("sha_init_padding()\n")).unwrap();
        }
        global_state.sha_init_pos = (global_state.sha_init_pos + 1) % 4;
    } else if insn[MACRO_SHA_LOAD] == 1 {
        if insn[MACRO_OPERAND_2] == 0 {
            w.write_fmt(format_args!(
                "sha_load_from_montgomery(m[{}].0)\n",
                insn[MACRO_OPERAND_0]
            ))
            .unwrap();
        } else {
            w.write_fmt(format_args!(
                "sha_load(m[{}].0 + m[{}].1 << 16)\n",
                insn[MACRO_OPERAND_0], insn[MACRO_OPERAND_0]
            ))
            .unwrap();
        }
    } else if insn[MACRO_SHA_MIX] == 1 {
        w.write_fmt(format_args!("sha_mix()\n")).unwrap();
    } else if insn[MACRO_SHA_FINI] == 1 {
        if global_state.sha_fini_pos == 0 {
            let out_addr = insn[MACRO_OPERAND_0] - 3;

            w.write_fmt(format_args!(
                "sha_fini(&mut m[{}..{}])\n",
                out_addr,
                out_addr + 8
            ))
            .unwrap();
        } else {
            w.write_fmt(format_args!("sha_fini_padding()\n")).unwrap();
        }
        global_state.sha_fini_pos = (global_state.sha_fini_pos + 1) % 4;
    } else if insn[MACRO_WOM_INIT] == 1 {
        w.write_fmt(format_args!("wom_init()\n")).unwrap();
    } else if insn[MACRO_WOM_FINI] == 1 {
        w.write_fmt(format_args!("wom_fini()\n")).unwrap();
    } else if insn[MACRO_SET_GLOBAL] == 1 {
        w.write_fmt(format_args!(
            "set_global(m[{}], {})\n",
            insn[MACRO_OPERAND_0], insn[MACRO_OPERAND_1],
        ))
        .unwrap();
    } else {
        println!("{:?}", insn);
        panic!("unknown instruction");
    }
}

fn walk_micro<W: Write>(global_state: &mut GlobalState, w: &mut W, insn: &[u32]) {
    let group = [
        [insn[7], insn[8], insn[9], insn[10]],
        [insn[11], insn[12], insn[13], insn[14]],
        [insn[15], insn[16], insn[17], insn[18]],
    ];

    for (i, row) in group.iter().enumerate() {
        w.write_fmt(format_args!("{}: ", global_state.line_no))
            .unwrap();
        if row[0] == MICRO_CONST {
            if row[2] == 0 {
                w.write_fmt(format_args!(
                    "m[{}] = ({})\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1],
                ))
                .unwrap();
            } else {
                w.write_fmt(format_args!(
                    "m[{}] = ({}, {})\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1],
                    row[2]
                ))
                .unwrap();
            }
        } else if row[0] == MICRO_ADD {
            w.write_fmt(format_args!(
                "m[{}] = m[{}] + m[{}]\n",
                insn[WRITE_ADDR] as usize + i,
                row[1],
                row[2]
            ))
            .unwrap();
        } else if row[0] == MICRO_SUB {
            w.write_fmt(format_args!(
                "m[{}] = m[{}] - m[{}]\n",
                insn[WRITE_ADDR] as usize + i,
                row[1],
                row[2]
            ))
            .unwrap();
        } else if row[0] == MICRO_MUL {
            w.write_fmt(format_args!(
                "m[{}] = m[{}] * m[{}]\n",
                insn[WRITE_ADDR] as usize + i,
                row[1],
                row[2]
            ))
            .unwrap();
        } else if row[0] == MICRO_INV {
            if row[2] == 0 {
                w.write_fmt(format_args!(
                    "m[{}] = (!m[{}].0)\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1]
                ))
                .unwrap();
            } else {
                w.write_fmt(format_args!(
                    "m[{}] = 1 / m[{}]\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1]
                ))
                .unwrap();
            }
        } else if row[0] == MICRO_EQ {
            w.write_fmt(format_args!("assert_eq!(m[{}], m[{}])\n", row[1], row[2]))
                .unwrap();
        } else if row[0] == MICRO_READ_IOP_HEADER {
            w.write_fmt(format_args!(
                "iop = read_iop(IOP_Header {{ count: {}, k_and_flip_flag: {}}})\n",
                row[1], row[2]
            ))
            .unwrap();
        } else if row[0] == MICRO_READ_IOP_BODY {
            w.write_fmt(format_args!(
                "m[{}] = iop.pop()\n",
                insn[WRITE_ADDR] as usize + i
            ))
            .unwrap();
        } else if row[0] == MICRO_MIX_RNG {
            if row[3] != 0 {
                w.write_fmt(format_args!("m[{}] = (({} * m[{}].0) << 64 + m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0)\n",
                    insn[WRITE_ADDR]  as usize + i,  row[3], insn[WRITE_ADDR]  as usize  + i - 1, row[1], row[1], row[2], row[2]
                )).unwrap();
            } else {
                w.write_fmt(format_args!(
                    "m[{}] = (m[{}].1 << 48 + m[{}].0 << 32 + m[{}].1 << 16 + m[{}].0)\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1],
                    row[1],
                    row[2],
                    row[2]
                ))
                .unwrap();
            }
        } else if row[0] == MICRO_SELECT {
            if row[3] >= 1006632960u32 {
                let num = 2013265921 - row[3];
                w.write_fmt(format_args!(
                    "m[{}] = m[{} - {} * m[{}].0]\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[2],
                    num,
                    row[1]
                ))
                .unwrap();
            } else {
                w.write_fmt(format_args!(
                    "m[{}] = m[{} + {} * m[{}].0]\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[2],
                    row[3],
                    row[1]
                ))
                .unwrap();
            }
        } else if row[0] == MICRO_EXTRACT {
            if row[2] == 1 && row[3] == 1 {
                w.write_fmt(format_args!(
                    "m[{}] = (m[{}].3)\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1]
                ))
                .unwrap();
            } else if row[2] == 0 && row[3] == 1 {
                w.write_fmt(format_args!(
                    "m[{}] = (m[{}].1)\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1]
                ))
                .unwrap();
            } else if row[2] == 1 && row[3] == 0 {
                w.write_fmt(format_args!(
                    "m[{}] = (m[{}].2)\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1]
                ))
                .unwrap();
            } else if row[2] == 0 && row[3] == 0 {
                w.write_fmt(format_args!(
                    "m[{}] = (m[{}].0)\n",
                    insn[WRITE_ADDR] as usize + i,
                    row[1]
                ))
                .unwrap();
            } else {
                println!("{:?}", insn);
                panic!("unknown instruction");
            }
        } else {
            println!("{:?}", insn);
            panic!("unknown instruction");
        }
    }
}

fn walk<W: Write>(w: &mut W, code: &[u32]) {
    let mut global_state = GlobalState::default();

    println!("number of rows: {}", code.len() / 21);

    for (idx, insn) in code.chunks_exact(21).enumerate() {
        global_state.line_no = idx + 1;

        if insn[SELECT_MACRO_OPS] == 1 {
            walk_macro(&mut global_state, w, insn);
        } else if insn[SELECT_MICRO_OPS] == 1 {
            walk_micro(&mut global_state, w, insn);
        } else if insn[SELECT_POSEIDON_LOAD] == 1 {
            w.write_fmt(format_args!("{}: ", global_state.line_no))
                .unwrap();
            w.write_fmt(format_args!(
                "poseidon.add_consts = {}; ",
                insn[POSEIDON_LOAD_ADD_CONSTS],
            ))
            .unwrap();
            let group = insn[POSEIDON_LOAD_G1] + insn[POSEIDON_LOAD_G2] * 2;
            if insn[POSEIDON_LOAD_KEEP_STATE] != 1 {
                if insn[POSEIDON_LOAD_DO_MONT] != 0 {
                    w.write_fmt(format_args!("poseidon.state{} = to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)\n",
                                         group, insn[13], insn[14], insn[15], insn[16], insn[17], insn[18], insn[19], insn[20]
                )).unwrap();
                } else {
                    w.write_fmt(format_args!("poseidon.state{} = (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)\n",
                                         group, insn[13], insn[14], insn[15], insn[16], insn[17], insn[18], insn[19], insn[20]
                    )).unwrap();
                }
            } else {
                if insn[POSEIDON_LOAD_DO_MONT] != 0 {
                    w.write_fmt(format_args!("poseidon.state{} += to_montgomery!(m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)\n",
                                         group, insn[13], insn[14], insn[15], insn[16], insn[17], insn[18], insn[19], insn[20]
                    )).unwrap();
                } else {
                    w.write_fmt(format_args!("poseidon.state{} += (m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0, m[{}].0)\n",
                                         group, insn[13], insn[14], insn[15], insn[16], insn[17], insn[18], insn[19], insn[20]
                    )).unwrap();
                }
            }
        } else if insn[SELECT_POSEIDON_FULL] == 1 {
            w.write_fmt(format_args!("{}: ", global_state.line_no))
                .unwrap();
            w.write_fmt(format_args!("poseidon.full()\n")).unwrap();
        } else if insn[SELECT_POSEIDON_PARTIAL] == 1 {
            w.write_fmt(format_args!("{}: ", global_state.line_no))
                .unwrap();
            w.write_fmt(format_args!("poseidon.partial()\n")).unwrap();
        } else if insn[SELECT_POSEIDON_STORE] == 1 {
            w.write_fmt(format_args!("{}: ", global_state.line_no))
                .unwrap();
            let group = insn[POSEIDON_LOAD_G1] + insn[POSEIDON_LOAD_G2] * 2;
            if insn[POSEIDON_LOAD_DO_MONT] != 0 {
                w.write_fmt(format_args!(
                    "poseidon.write_state{}_montgomery(&mut m[{}..{}])\n",
                    group,
                    insn[WRITE_ADDR],
                    insn[WRITE_ADDR] + 8
                ))
                .unwrap();
            } else {
                w.write_fmt(format_args!(
                    "poseidon.write_state{}(&mut m[{}..{}])\n",
                    group,
                    insn[WRITE_ADDR],
                    insn[WRITE_ADDR] + 8
                ))
                .unwrap();
            }
        } else {
            println!("{:?}", insn);
            panic!("unknown instruction");
        }
    }
}

fn main() {
    let args = Args::parse();

    let f = File::open(args.file.clone()).unwrap();
    let mut buf_reader = BufReader::new(f);

    let mut u8vec: Vec<u8> = Vec::new();
    buf_reader.read_to_end(&mut u8vec).unwrap();

    let code: Vec<u32> = Vec::from(bytemuck::cast_slice(u8vec.as_slice()));

    let out_name = if args.output.is_some() {
        args.output.unwrap()
    } else {
        let tmp = String::from(Path::new(&args.file).file_name().unwrap().to_str().unwrap());
        if tmp.ends_with(".zkr") {
            String::from(&tmp.as_str()[0..tmp.len() - 4]) + ".ll0"
        } else {
            tmp + ".ll0"
        }
    };

    let ff = File::create(out_name).unwrap();
    let mut buf_writer = BufWriter::new(ff);
    walk(&mut buf_writer, &code);
}
