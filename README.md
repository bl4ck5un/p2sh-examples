Constructing P2SH transactions in Rust
======================================

# The example of CheckLocktimeVerify


## Usage

`cltv.rs` implements the same functionality as Peter Todd's [CLTV-demo](https://github.com/bl4ck5un/checklocktimeverify-demos). `cltv` has two subcommands: `create` and `spend`. The former generates a `P2SH` address such that coins sent to it can be spent by the specified secret key after the specified timeout (an absolute unix epoch).

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

## Example

Reference output:

```
> python3 hodl.py -vt cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5 1547501293 create
> 2MxuEFzoSmvZSzaUm4LgrNSXUauwYCq1ntQ
```

One can verify that `cltv` outputs the same address:

```
> ./target/debug/cltv --locktime 1547501293 --secret cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5 create
> 2MxuEFzoSmvZSzaUm4LgrNSXUauwYCq1ntQ
```
