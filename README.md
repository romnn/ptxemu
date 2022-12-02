## PTXemu

`ptxemu` is a work in progress parallel emulator for the NVIDIA PTX virtual instruction set (ISA).

#### Installation

```bash
cargo install ptxemu --bin emulator
```

#### Benchmarking

t.b.a

#### Usage

t.b.a

#### Linting

```bash
cargo clippy --tests --benches --examples --all-features -- -Dclippy::all -Dclippy::pedantic
```

#### TODO

In general:
- avoid writing production quality code
- always focus on the goal
- note the opportunities for improvement for later but do not actually do them
- always choose the quickest way to get there

- add compile helpers to compile applications for different CUDA versions using testcontainers and docker images from nvidia
- add run helpers that can run CUDA applications (requires CUDA capable GPU) to check for functional correctness
- implemet the parser first
    - test it can parse PTX for all CUDA versions and the full CUDA SDK
    - write an AST representation
- implement a very simple serial emulator
- from there, see how far we want to go with parallel emulation
