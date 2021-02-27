build:
	CC=musl-gcc cargo build --release --target=x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/release/rs_yara output/main
build-debug:
	CC=musl-gcc cargo build --target=x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/debug/rs_yara output/main