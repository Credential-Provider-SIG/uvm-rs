use std::path::PathBuf;

use rusqlite::Connection;

use crate::{crypto::LocalKeyPair, load_file, model::fetch_passkeys, schema::Vault, write_file};

pub fn export(conn: &Connection, path: PathBuf) -> Result<(), clap::Error> {
    let open_box = load_file(&path)?;
    let vault = Vault {
        passkeys: fetch_passkeys(conn).map_err(|_| {
            clap::Error::raw(
                clap::error::ErrorKind::Io,
                "Could not fetch passkeys from database",
            )
        })?,
    };

    let rng = ring::rand::SystemRandom::new();

    let keys = LocalKeyPair::new(&rng)?;

    let sealed = keys.seal(open_box, vault, &rng)?;

    write_file(path, &sealed)
}
