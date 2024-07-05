use std::str::FromStr;

use rusqlite::{params, Connection, Error};
use tabled::Tabled;

pub struct Database {
    conn: Connection,
}

#[derive(Tabled)]
pub struct ImageQueryResult {
    cve: String,
    package: String,
    severity: String,
    installed_version: String,
    fixed_version: String,
}

#[derive(Tabled)]
pub struct VulnerabilityQueryResult {
    image: String,
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
                severity VARCHAR NOT NULL,
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
        severity: &str,
    ) -> Result<usize, Error> {
        return self.conn.execute(
            "INSERT OR IGNORE INTO cves(cve, package, fixed_version, severity) VALUES (?1, ?2, ?3, ?4)",
            params![cve, package, fixed_version, severity],
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

    pub fn get_cves(&self, target: &str, severity: &Option<String>) -> Vec<ImageQueryResult> {
        let query_result = self.conn.prepare(
            "SELECT vulns.cve, package, severity, installed_version, fixed_version 
            FROM image_vulnerabilities as vulns 
            INNER JOIN cves 
            ON cves.cve=vulns.cve 
            WHERE image=?1 
            AND severity LIKE ?2",
        );

        return match query_result {
            Ok(mut statement) => statement
                .query_map(
                    params![
                        target,
                        severity.clone().unwrap_or(String::from_str("%").unwrap())
                    ],
                    |row| {
                        Ok(ImageQueryResult {
                            cve: row.get(0)?,
                            package: row.get(1)?,
                            severity: row.get(2)?,
                            installed_version: row.get(3)?,
                            fixed_version: row.get(4)?,
                        })
                    },
                )
                .unwrap()
                .filter_map(Result::ok)
                .collect(),

            Err(e) => {
                eprintln!("Cannot query rows {}", e);
                return Vec::new();
            }
        };
    }

    pub fn get_targets_with_cve(&self, target: &str) -> Vec<VulnerabilityQueryResult> {
        let query_result = self.conn.prepare(
            "SELECT image FROM image_vulnerabilities
            WHERE cve=?1",
        );

        return match query_result {
            Ok(mut statement) => statement
                .query_map(params![target], |row| {
                    Ok(VulnerabilityQueryResult { image: row.get(0)? })
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
