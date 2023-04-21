use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::mpsc,
};

use notify::{Event, Watcher};
use rusqlite::Connection;

use crate::{
    crypto::LocalKeyPair,
    list, load_file,
    model::store_passkeys,
    schema::{SealedBox, ToFileExtension},
    write_file,
};

pub fn import(conn: &mut Connection, path: PathBuf) -> Result<(), clap::Error> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = LocalKeyPair::new(&rng)?;

    let open_box = key_pair.to_open_box()?;

    let dir = if path.extension().is_some() {
        path.parent().unwrap_or(Path::new("."))
    } else {
        &path
    };
    if !dir.exists() {
        create_dir_all(dir)?;
    }
    write_file(path.clone(), &open_box)?;

    println!("Waiting for Sealed box in {}", dir.display());
    let (sender, recv) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = notify::recommended_watcher(sender).map_err(|_| {
        clap::Error::raw(
            clap::error::ErrorKind::Io,
            format!("Cannot watcher for directory {}", dir.display()),
        )
    })?;

    watcher
        .watch(dir, notify::RecursiveMode::NonRecursive)
        .map_err(|_| {
            clap::Error::raw(
                clap::error::ErrorKind::Io,
                format!("Cannot watcher for directory {}", dir.display()),
            )
        })?;

    let sealed_path = loop {
        let Ok(Ok(event)) = recv.recv() else {
            return Err(clap::Error::raw(clap::error::ErrorKind::Io, "failed to read from directory"))
        };
        let Some(sealed_path) = event
                .paths
                .into_iter()
                .find(|path| path.extension().filter(|ext| *ext == SealedBox::FILE_EXT).is_some()) else {
                    continue;
                };
        break sealed_path;
    };

    let sealed = load_file(&sealed_path)?;
    let vault = key_pair.open(sealed)?;

    store_passkeys(conn, &vault.passkeys).map_err(|_| {
        clap::Error::raw(
            clap::error::ErrorKind::Io,
            "Could not store imported passkeys",
        )
    })?;

    list(&vault.passkeys);

    Ok(())
}
