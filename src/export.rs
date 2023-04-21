use rusqlite::Connection;

use crate::{
    crypto::LocalKeyPair,
    model::fetch_passkeys,
    schema::{OpenBox, SealedBox, Vault},
};

pub fn export(conn: &Connection, open_box: OpenBox) -> Result<SealedBox, clap::Error> {
    let vault = Vault {
        passkeys: fetch_passkeys(conn).map_err(|_| {
            clap::Error::raw(
                clap::error::ErrorKind::Io,
                "Could not fetch passkeys from database",
            )
        })?,
    };
    dbg!(&vault);

    let rng = ring::rand::SystemRandom::new();

    let keys = LocalKeyPair::new(&rng).ok_or_else(|| {
        clap::Error::raw(
            clap::error::ErrorKind::Io,
            "Could not generate local key pair",
        )
    })?;

    keys.seal(open_box, vault, &rng)
        .map_err(|e| clap::Error::raw(clap::error::ErrorKind::Io, e))
}
