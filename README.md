# first-rewrite

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
 cargo xtask build-ebpf && cargo build && sudo RUST_LOG=debug ./target/debug/first-rewrite --src 8081 --dst 8082
 ```
Note: for OS's other than Ubuntu 22.10 you may need to pass a different `--cgroup-path`.