# caracat

[![crates.io](https://img.shields.io/crates/v/caracat?logo=rust)](https://crates.io/crates/caracat/)
[![docs.rs](https://img.shields.io/docsrs/caracat?logo=docs.rs)](https://docs.rs/caracat/)
[![test](https://img.shields.io/github/actions/workflow/status/maxmouchet/caracat/test.yml?logo=github&label=test)](https://github.com/maxmouchet/caracat/actions/workflows/test.yml)
[![publish](https://img.shields.io/github/actions/workflow/status/maxmouchet/caracat/publish.yml?logo=github&label=publish)](https://github.com/maxmouchet/caracat/actions/workflows/publish.yml)

caracat (always in lowercase) is a port of [caracal](https://github.com/dioptra-io/caracal/) from C++ to Rust.

The initial motivation was to benefit from a saner build system to make the project easier to maintain.
The architecture is very similar between the two projects and the input/output format is the same.

Two example binaries are provided:
```bash
# Implementation of caracal command-line interface
cargo run --example caracal -- --help
# (Partial) implementation of yarrp
cargo run --example yarrp -- --help
```

For more information, please refer to the [caracal documentation](https://dioptra-io.github.io/caracal/) and to the [API documentation](https://docs.rs/caracat/latest/caracat/).
