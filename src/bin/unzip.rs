use clap::Parser;
use std::fs::File;
use std::io::{BufReader, Read, Write};

#[derive(Parser, Debug)]
#[command(about = "Unzip the ZIP file that consists of ZKRs", long_about = None)]
struct Args {
    // Filename of the ZKR file to be unzipped
    #[arg(short, long, required = true)]
    file: String,

    // Output directory
    #[arg(short, long, default_value = "./")]
    output: String,
}

fn main() {
    let args = Args::parse();

    let f = File::open(args.file).unwrap();
    let buf_reader = BufReader::new(f);

    let mut z = zip::ZipArchive::new(buf_reader).unwrap();

    for i in 0..z.len() {
        let mut file = z.by_index(i).unwrap();

        let mut buf = Vec::<u8>::new();
        file.read_to_end(&mut buf).unwrap();

        let mut ff = File::create(format!("{}{}", args.output, file.name())).unwrap();
        ff.write(&buf).unwrap();
    }
}
