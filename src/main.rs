use anyhow::Result;
use std::fs::File;
use std::io::Write;

mod task1;

use clap::{AppSettings, Clap};
use std::path::PathBuf;

/// Solutions for the PKI lecture SoSe21
#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// sub command to solve task one, hash will be printed to stdout
    Task1(Task1),
}

#[derive(Clap)]
struct Task1 {
    name: String,
    email: String,
    matrikel_no: String,
    /// Where to store the encrypted input
    file_name: PathBuf,
}



fn main() -> Result<()>{
    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Task1(Task1 { name, email, matrikel_no, file_name }) => {
            let res = task1::solve(&name, &email, &matrikel_no)?;
            let mut f = File::create(file_name)?;
            f.write_all(res.encoded_enc.as_bytes())?;
            println!("Hash: {}", res.encoded_hash);
        }
    }
    Ok(())
}
