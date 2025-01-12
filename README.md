# caracat

[![crates.io](https://img.shields.io/crates/v/caracat?logo=rust)](https://crates.io/crates/caracat/)
[![docs.rs](https://img.shields.io/docsrs/caracat?logo=docs.rs)](https://docs.rs/caracat/)
[![test](https://img.shields.io/github/actions/workflow/status/maxmouchet/caracat/test.yml?logo=github&label=test)](https://github.com/maxmouchet/caracat/actions/workflows/test.yml)

caracat (always in lowercase) is a port of [caracal](https://github.com/dioptra-io/caracal/) from C++ to Rust.

The initial motivation was to benefit from a saner build system to make the project easier to maintain.
The architecture is very similar between the two projects and the input/output format is the same.
Versions > 1.0.0 might break this compatibility to fix some idiosyncrasies inherited by caracal.

Multiple example binaries are provided:
```bash
# Traceroute tool
cargo run --example traceoute -- --help
# Implementation of yarrp
cargo run --example yarrp -- --help
```

Example traceroute run:
```bash
# cargo run --example traceroute -- --as-path-lookups --first=3 google.com
traceroute to 2a00:1450:4007:80e::200e (google.com), 30 hops max, ?? byte packets
 3  2a01:cfc0:200:8000:193:252:102:135 (2a01:cfc0:200:8000:193:252:102:135) [AS5511] 8.9ms
 4  bundle-ether149.pastr4.paris.opentransit.net (2a01:cfc4:0:400::3) [AS5511] 83.6ms
 5  2001:4860:1:1::524 (2001:4860:1:1::524) [AS15169] 9.0ms
 6  2a00:1450:80a9::1 (2a00:1450:80a9::1) [AS15169] 9.0ms
 7  2001:4860:0:1::7002 (2001:4860:0:1::7002) [AS15169] 10.7ms
 8  2001:4860:0:1::1f95 (2001:4860:0:1::1f95) [AS15169] 9.4ms
 9  par10s42-in-x0e.1e100.net (2a00:1450:4007:80e::200e) [AS15169] 10.6ms
```

For more information, please refer to the [caracal documentation](https://dioptra-io.github.io/caracal/) and to the [API documentation](https://docs.rs/caracat/latest/caracat/).
