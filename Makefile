all:
	cargo build

fips:
	cargo build --features fips

check:
	cargo test

check-fips:
	cargo test --features fips

check-format:
	@find . -not \( -path ./target -prune \) -type f -name '*.rs' ! -name 'bindings.rs' | xargs rustfmt --check --color auto --edition 2021

fix-format:
	@find . -not \( -path ./target -prune \) -type f -name '*.rs' ! -name 'bindings.rs' | xargs rustfmt --edition 2021

check-spell:
	@.github/codespell.sh
