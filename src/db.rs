use rusqlite::{params, Connection, Error};

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(db_path: &str) -> Result<Self, Error> {
        let conn = Connection::open(db_path)?;
        conn.execute("PRAGMA foreign_keys = ON;", params![])?;

        let database = Database { conn };
        database.create_table();

        Ok(database)
    }

    fn create_table(&self) -> () {
        let _ = self.conn.execute(
            "CREATE TABLE IF NOT EXISTS cves (
                cve VARCHAR NOT NULL PRIMARY KEY,
                package VARCHAR NOT NULL,
                fixed_version VARCHAR,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        );

        let _ = self.conn.execute(
            "CREATE TABLE IF NOT EXISTS image_vulnerabilities (
                image VARCHAR NOT NULL,
                cve VARCHAR NOT NULL,
                installed_version VARCHAR NOT NULL,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (image, cve),
                FOREIGN KEY (cve) REFERENCES cves (cve)
            )",
            [],
        );
    }

    pub fn insert_cve(
        &self,
        cve: &str,
        package: &str,
        fixed_version: &str,
    ) -> Result<usize, Error> {
        return self.conn.execute(
            "INSERT OR IGNORE INTO cves(cve, package, fixed_version) VALUES (?1, ?2, ?3)",
            params![cve, package, fixed_version],
        );
    }

    pub fn insert_vuln(
        &self,
        target: &str,
        cve: &str,
        installed_version: &str,
    ) -> Result<usize, Error> {
        return self.conn.execute(
            "INSERT OR IGNORE INTO image_vulnerabilities(image, cve, installed_version) VALUES (?1, ?2, ?3)",
            params![
                target,
                cve,
                installed_version
            ],
        );
    }

    pub fn get_cves(&self, target: &str) -> Vec<String> {
        let query_result = self
            .conn
            .prepare("SELECT cve FROM image_vulnerabilities where image=?1");

        return match query_result {
            Ok(mut statement) => statement
                .query_map(params![target], |row| {
                    let cve: String = row.get(0)?;
                    Ok(cve)
                })
                .unwrap()
                .filter_map(Result::ok)
                .collect(),

            Err(e) => {
                eprintln!("Cannot query rows {}", e);
                return Vec::new();
            }
        };
    }
}
