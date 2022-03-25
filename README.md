# tracker

tracker detects, logs, and blocks port scanning on IPv4 and IPv6 using XDP.

## Prerequisites

1. Install `rustup` and `cargo` [here](https://www.rust-lang.org/learn/get-started)
1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Building tracker

### eBPF
```bash
make ebpf
```

### Userspace

```bash
make release
```

## Run

```bash
sudo ./target/release/tracker ./target/bpfel-unknown-none/release/tracker
```
