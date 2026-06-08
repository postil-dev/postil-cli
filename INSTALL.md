# Installation

Postil CLI ships the `postil` binary. Use the install path that matches your
environment.

## Cargo install

This is the fastest route for most users and CI images:

```bash
cargo install --git https://github.com/postil-dev/postil-cli --locked --force
```

## Local development

Build and run the binary from a checkout when iterating on the CLI itself:

```bash
cargo install --path . --locked --force
cargo build --release
```

## CI or container images

Install from source in a build step, then invoke the resulting `postil` binary
directly:

```bash
cargo install --path . --locked --force
postil review --repo owner/repo --pr 123 --sha HEAD_SHA
```
