use clap::Parser;
use ll0::parser::Code;
use ll0::pass::const_pass::ConstPass;
use ll0::pass::live_variable_analysis::LiveVariableAnalysisPass;
use ll0::pass::merge_iop_pass::MergeIOPPass;
use ll0::pass::poseidon_pass::PoseidonPass;
use ll0::pass::sha_pass::ShaPass;
use ll0::pass::Pass;
use ll0::structures::StructuredInstruction;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

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

fn main() {
    let args = Args::parse();

    let f = File::open(args.file.clone()).unwrap();
    let mut buf_reader = BufReader::new(f);

    let mut u8vec: Vec<u8> = Vec::new();
    buf_reader.read_to_end(&mut u8vec).unwrap();

    let u32vec: Vec<u32> = Vec::from(bytemuck::cast_slice(u8vec.as_slice()));
    let mut code = Code::try_from(u32vec.as_slice()).unwrap();

    ConstPass::pass(&mut code).unwrap();
    MergeIOPPass::pass(&mut code).unwrap();
    LiveVariableAnalysisPass::pass(&mut code).unwrap();
    ShaPass::pass(&mut code).unwrap();
    PoseidonPass::pass(&mut code).unwrap();

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

    for (insn, line_no) in code.0.iter() {
        match insn {
            StructuredInstruction::__DELETE__ => {}
            _ => {
                buf_writer
                    .write_fmt(format_args!("{}: {}\n", line_no, insn))
                    .unwrap();
            }
        }
    }
}
