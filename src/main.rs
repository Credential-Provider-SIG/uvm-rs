use std::{
    fs::{read_dir, File},
    path::{Path, PathBuf},
};

use clap::Parser;
use model::fetch_passkeys;
use schema::{Passkey, ToFileExtension};
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};

mod cli;
mod crypto;
mod export;
mod import;
mod model;
mod schema;

fn main() {
    let args = cli::Cli::parse();
    let mut db_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => clap::Error::from(e).exit(),
    };
    db_path.set_file_name("uvm-rs.db");
    let mut conn = model::create_db(&db_path).unwrap();
    let res = match args.operation {
        cli::Operation::Import(i) => import::import(&mut conn, i.path),
        cli::Operation::Export(e) => export::export(&conn, e.path),
        cli::Operation::List => {
            let pks = fetch_passkeys(&conn).unwrap();
            list(&pks);
            Ok(())
        }
    };
    if let Err(e) = res {
        e.exit()
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
    // if extension exists, assume its a file, otherwise, assume a folder
    let file = if path.extension().is_some() && path.set_extension(extension) {
        File::create(path)?
    } else {
        // must be a directory
        path.push(format!("uvm-rs.{extension}"));
        File::create(path)?
    };
    serde_json::to_writer_pretty(file, contents)
        .map_err(|e| clap::Error::raw(clap::error::ErrorKind::Io, e))
}

fn list(passkeys: &[Passkey]) {
    println!("{}", Table::new(passkeys).with(Style::markdown()))
}
