prog := hebe
release_target_path := ./target/release/

debug ?=

ifdef debug
  release :=
  target :=debug
  extension :=debug
else
  release :=--release
  target :=release
  extension :=
endif

clean:
	cargo clean

build:
	cargo build $(release)

all: clean build
 
help:
	@echo "usage: $(release_target_path)$(prog) --help"
