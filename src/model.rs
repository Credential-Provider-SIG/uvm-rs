use std::path::Path;

use rusqlite::{types::FromSqlError, Connection, Result};

use crate::schema::{base64, try_from_base64, Passkey};

/// The database is NOT encrypted because this is for demonstration purposes
pub fn create_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;

    conn.execute_batch(include_str!("model.sql"))?;
    Ok(conn)
}

pub fn fetch_passkeys(conn: &Connection) -> Result<Vec<Passkey>> {
    let mut stmt = conn.prepare(
        r#"SELECT
            "id",
            "rp_id",
            "rp_name",
            "user_id",
            "username",
            "counter",
            "key"
        from "passkeys""#,
    )?;

    let res = stmt.query_map([], |row| {
        Ok(Passkey {
            credential_id: row.get("id")?,
            relying_party_id: row.get("rp_id")?,
            relying_party_name: row.get("rp_name")?,
            user_handle: row.get("user_id")?,
            user_display_name: row.get("username")?,
            counter: row.get::<_, u64>("counter")?.to_string(),
            private_key: try_from_base64(row.get_ref("key")?.as_str()?)
                .ok_or(FromSqlError::InvalidType)?,
        })
    })?;
    res.collect()
}

pub fn store_passkeys(conn: &mut Connection, passkeys: &[Passkey]) -> Result<()> {
    let tx = conn.transaction()?;
    let mut stmt = tx.prepare(
        r#"INSERT OR REPLACE INTO passkeys(
            "id",
            "rp_id",
            "rp_name",
            "user_id",
            "username",
            "counter",
            "key"
        )
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )?;

    for pk in passkeys {
        stmt.execute((
            &pk.credential_id,
            &pk.relying_party_id,
            &pk.relying_party_name,
            &pk.user_handle,
            &pk.user_display_name,
            pk.counter.parse::<u64>().unwrap(),
            base64(&pk.private_key),
        ))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::mock_vault;

    use super::{create_db, fetch_passkeys, store_passkeys};

    #[test]
    fn database_round_trip() {
        let mut passkeys = mock_vault().passkeys;
        passkeys.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
        let mut conn =
            create_db("file::memory:".as_ref()).expect("could not create in memory database");
        store_passkeys(&mut conn, &passkeys).expect("could not store passkeys");
        let mut retrieved = fetch_passkeys(&conn).expect("could not load stored passkeys");
        retrieved.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));

        for (expected, stored) in passkeys.into_iter().zip(retrieved) {
            assert_eq!(
                expected, stored,
                "expected {:#?} != stored {:#?}",
                expected, stored
            );
        }
    }
}
