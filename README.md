# hebe
Radisys Vulnerability Assessment and Management System

## Install Hebe
This project is written in Rust, and uses databases.

**Important** Please note that Database configurations is a prerequestie
### Prerequistie
    * [Rust and Cargo](https://www.rust-lang.org/tools/install) installed
    * Database needs to be configured.

#### Step 1: Clone Repo
```bash
git clone https://github.com/rsys-fchaliss/hebe && cd hebe
```
#### Step 2: Build from source
Run the following command to build the hebe CLI from source. This will compile the code and create an optimized binary in `target/release`.
```bash
$ cargo build --release
```
##### Usage

Once installed, it's easy to use the hebe CLI. Each operation starts with:

```bash
./target/release/hebe [arguments]
```

Here's a simple example. By default, the hebe CLI will print the summary to terminal unless otherwise specified:

```bash
./target/release/hebe -i ./config.toml -v true
```

##### Options
Radisys Vulnerability Assessment Manager

Usage: alex [OPTIONS] --input-config-file <INPUT_CONFIG_FILE>

Options:
  -i, --input-config-file <INPUT_CONFIG_FILE>

  -o, --output-type <OUTPUT_TYPE>
          [default: Terminal] [possible values: terminal, text, word, markdown, slack]
  -v, --verbose <VERBOSE>
          [default: false]
  -h, --help
          Print help
  -V, --version
          Print version

Vulnerability Manager for details reachout x@radisys.com





