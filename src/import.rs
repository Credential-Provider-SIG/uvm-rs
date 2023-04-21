use std::{path::PathBuf, sync::mpsc};

use notify::{event::CreateKind, Event, EventKind, Watcher};
use rusqlite::Connection;

use crate::{
    crypto::LocalKeyPair,
    load_file,
    model::store_passkeys,
    schema::{SealedBox, ToFileExtension},
    write_file,
};

pub fn import(conn: &mut Connection, dir: PathBuf) -> Result<(), clap::Error> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = LocalKeyPair::new(&rng).unwrap();

    let open_box = key_pair.to_open_box().unwrap();

    write_file(dir.clone(), &open_box)?;

    println!("Waiting for Sealed box in {}", dir.display());
    let (sender, recv) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = notify::recommended_watcher(sender).unwrap();

    watcher
        .watch(&dir, notify::RecursiveMode::NonRecursive)
        .unwrap();

    let sealed_path = loop {
        let Ok(Ok(event)) = recv.recv() else {
            panic!("oh no");
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
    let vault = key_pair.open(sealed).unwrap();

    println!("{:#?}", vault);

    store_passkeys(conn, &vault.passkeys).unwrap();

    Ok(())
}
