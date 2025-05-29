# Contributing

## IDE Configuration
When working with VSCode, enable the following settings so that `rust-analyzer` can provide code completion suggestions for `rustc` libraries.
```
{
    "rust-analyzer.cargo.sysroot": "discover",
    "rust-analyzer.rustc.source": "discover"
}
```