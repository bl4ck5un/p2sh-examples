# Constructing P2SH transactions in Rust

This repo contains educational (hopefully) examples for handcrafting pay-to-script-hash transactions in Rust.

## A simple one: hodl coins using CheckLocktimeVerify

`cltv.rs` is inspired by Peter Todd's CLTV demo (see a [fork of mine](https://github.com/bl4ck5un/checklocktimeverify-demos)).
`cltv` has two subcommands: `create` and `spend`. The former generates a `P2SH`
address such that coins sent to it can be spent by the specified secret key
after the specified timeout (an absolute unix epoch).

### Usage


```
USAGE:
    cltv --locktime <LOCKTIME> --secret <SECRET_KEY> create

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
```

The latter generate a transaction that spends an P2SH UTXO to a specified address.

```
USAGE:
    cltv --locktime <LOCKTIME> --secret <SECRET_KEY> spend [OPTIONS] --address <target> --tx <transaction_hex>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --address <target>
        --tx <transaction_hex>
        --vout <vout>              [default: 0]
```

See `cltv --help` for the usage info.

## Tips

- Use the attached config file to create a regtest for fast testing.
- Make sure the P2SH UTXO is confirmed before trying to spend it. Otherwise you might a `non-final` error, even the timelock has expired.
