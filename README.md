# hebe

Radisys Vulnerability Assessment and Management System

## Install Hebe

This project is written in Rust, and uses `sqlite3` to store data.

### Prerequisite

-   [Rust and Cargo](https://www.rust-lang.org/tools/install) installed
-   [Trivy](https://github.com/aquasecurity/trivy) installed on host machine

#### Step 1: Clone Repo

```bash
git clone https://github.com/rsys-fchaliss/hebe && cd hebe
```

#### Step 2: Build from source

Run the following command to build the hebe CLI from source. This will compile the code and create an optimized binary in `target/release`.

```bash
$ cargo build --release
```

---

### Usage

Once installed, it's easy to use the hebe CLI. Each operation starts with:

```bash
./target/release/hebe [arguments]
```

---

### Options

All options can be listed using `--help` for a command or subcommand.

```
Radisys Vulnerability Assessment Manager

Usage: hebe <COMMAND>

Commands:
  scan
  query-vulnerabilities
  triage-vulnerability
  help                   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

Vulnerability Manager for details reachout x@radisys.com
```

---

### Sample usage

#### Scan a docker image for vulnerabilities

```
~ hebe scan --image artifactory.radisys.com:8088/mrfp:19.0.3.0.B-1
```

```
~ hebe scan --image artifactory.radisys.com:8088/mrfp:19.0.3.0.B-2
```

#### Query vulnerability by image/severity/vulnerability

```
~ hebe query-vulnerabilities --image artifactory.radisys.com:8088/mrfp:19.0.3.0.B-1

// Tabulated view of vulnerabilities in artifactory.radisys.com:8088/mrfp:19.0.3.0.B-1 image
```

```
~ hebe query-vulnerabilities --image artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 --severity MEDIUM
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| image                                             | cve            | package | severity | installed_version | fixed_version  | expected_image_fix_version |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2021-3572  | pip     | MEDIUM   | 9.0.3             | 21.1           |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2023-49082 | aiohttp | MEDIUM   | 3.8.6             | 3.9.0          |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2023-5752  | pip     | MEDIUM   | 21.3.1            | 23.3           |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2024-22195 | Jinja2  | MEDIUM   | 3.0.3             | 3.1.3          |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2024-23334 | aiohttp | MEDIUM   | 3.8.6             | 3.9.2          |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2024-23829 | aiohttp | MEDIUM   | 3.8.6             | 3.9.2          |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2024-27306 | aiohttp | MEDIUM   | 3.8.6             | 3.9.4          |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2024-34064 | Jinja2  | MEDIUM   | 3.0.3             | 3.1.4          |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2024-3651  | idna    | MEDIUM   | 3.6               | 3.7            |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2024-37891 | urllib3 | MEDIUM   | 1.26.18           | 1.26.19, 2.2.2 |                            |
+---------------------------------------------------+----------------+---------+----------+-------------------+----------------+----------------------------+
```

```
~ hebe query-vulnerabilities --cve CVE-2020-14343
+------------------------------------------------+
| image                                          |
+------------------------------------------------+
| artifactory.radisys.com:8088/oamp:19.0.3.0.B-1 |
+------------------------------------------------+
| artifactory.radisys.com:8088/oamp:19.0.3.0.B-2 |
+------------------------------------------------+
```

#### Triaging a vulnerability with expected fix version

```
~ hebe triage-vulnerability --image artifactory.radisys.com:8088/mrfp:19.0.3.0.B-1 --cve CVE-2021-3572 --version 19.1

+------------------------------------------------+---------------+---------+----------+-------------------+---------------+----------------------------+
| image                                          | cve           | package | severity | installed_version | fixed_version | expected_image_fix_version |
+------------------------------------------------+---------------+---------+----------+-------------------+---------------+----------------------------+
| artifactory.radisys.com:8088/mrfp:19.0.3.0.B-1 | CVE-2021-3572 | pip     | MEDIUM   | 9.0.3             | 21.1          | 19.1                       |
+------------------------------------------------+---------------+---------+----------+-------------------+---------------+----------------------------+
```

```
~ hebe triage-vulnerability --image artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 --cve CVE-2019-20916 --version 19.1

+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
| image                                             | cve            | package | severity | installed_version | fixed_version | expected_image_fix_version |
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2019-20916 | pip     | HIGH     | 9.0.3             | 19.2          | 19.1                       |
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+

```

```
~ hebe query-vulnerabilities --fix-version 19.1
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
| image                                             | cve            | package | severity | installed_version | fixed_version | expected_image_fix_version |
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
| artifactory.radisys.com:8088/mrfp:19.0.3.0.B-1    | CVE-2021-3572  | pip     | MEDIUM   | 9.0.3             | 21.1          | 19.1                       |
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
| artifactory.radisys.com:8088/oamp:19.0.3.0.B-2    | CVE-2020-1747  | PyYAML  | CRITICAL | 3.12              | 5.3.1         | 19.1                       |
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-2 | CVE-2019-20916 | pip     | HIGH     | 9.0.3             | 19.2          | 19.1                       |
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
| artifactory.radisys.com:8088/mrfctrl:19.0.3.0.B-1 | CVE-2019-20916 | pip     | HIGH     | 9.0.3             | 19.2          | 19.1                       |
+---------------------------------------------------+----------------+---------+----------+-------------------+---------------+----------------------------+
```
