use std::{
    fs::{read_dir, File},
    path::{Path, PathBuf},
};

use clap::Parser;
use schema::ToFileExtension;
use serde::{Deserialize, Serialize};

mod cli;
mod crypto;
mod export;
mod model;
mod schema;

fn main() -> Result<(), clap::Error> {
    let args = cli::Cli::parse();
    let conn = model::create_db("./uvm-rs.db".as_ref()).unwrap();
    match args.operation {
        cli::Operation::Import(_i) => todo!(),
        cli::Operation::Export(e) => {
            let open_box = load_file(&e.path)?;
            let sealed = export::export(&conn, open_box)?;
            write_file(e.path, &sealed)
        }
        cli::Operation::List => todo!(),
    }
}
fn load_file<T>(path: &Path) -> Result<T, clap::Error>
where
    T: for<'a> Deserialize<'a> + ToFileExtension,
{
    let extension = T::FILE_EXT;
    let file = if path.is_file() && path.extension().filter(|ext| ext == &extension).is_some() {
        File::open(path)?
    } else if let Some(file) = read_dir(path)?.find_map(|entry| {
        entry.ok().map(|entry| entry.path()).filter(|path| {
            if let Some(ext) = path.extension() {
                ext == extension
            } else {
                false
            }
        })
    }) {
        File::open(file)?
    } else {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::InvalidValue,
            format!("Could not find a file with the  .{extension} extension"),
        ));
    };
    serde_json::from_reader(file).map_err(|e| clap::Error::raw(clap::error::ErrorKind::Io, e))
}

fn write_file<T>(mut path: PathBuf, contents: &T) -> Result<(), clap::Error>
where
    T: Serialize + ToFileExtension,
{
    let extension = T::FILE_EXT;
    let file = if path.set_extension(extension) {
        File::create(path)?
    } else {
        // must be a directory
        path.set_file_name(format!("uvm-rs.{extension}"));
        File::create(path)?
    };
    serde_json::to_writer_pretty(file, contents)
        .map_err(|e| clap::Error::raw(clap::error::ErrorKind::Io, e))
}
