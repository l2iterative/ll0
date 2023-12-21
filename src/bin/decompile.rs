use clap::Parser;
use lowlevel0::parser::Code;
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
    let code = Code::try_from(u32vec.as_slice()).unwrap();

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
        buf_writer
            .write_fmt(format_args!("{}: {}\n", line_no, insn))
            .unwrap();
    }
}
