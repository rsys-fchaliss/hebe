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
~ hebe scan --image=ubuntu:24.04

// Tabulated view of vulnerabilities, also persisted to database
```

#### Query vulnerability by image/severity/vulnerability

```
~ hebe query-vulnerabilities --image=ubuntu:24.04

// Tabulated view of vulnerabilities in ubuntu:24.04 image
```

```
~ hebe query-vulnerabilities --image=ubuntu:24.04 --severity=MEDIUM

// Tabulated view of vulnerabilities in ubuntu:24.04 image with MEDIUM severity
```

```
~ hebe query-vulnerabilities --cve=CVE-2020-22916

// Tabulated view of images with specified CVE in them
```

#### Triaging a vulnerability with expected fix version

```
~ hebe triage-vulnerability --image=ubuntu:24.04 --cve=CVE-2020-22916 --version=1.2.3

// Tabulated view of issues expected to be fixed in version 1.2.3
```

```
~ hebe query-vulnerabilities --fix-version=1.2.3

// Tabulated view of issues expected to be fixed in version 1.2.3
```
