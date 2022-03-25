.PHONEY: all
all: ebpf release

.PHONEY: ebpf
ebpf:
	cargo xtask build-ebpf	

.PHONEY: release
release:
	cargo build --release

.PHONEY: lint
lint:
	cargo clippy
