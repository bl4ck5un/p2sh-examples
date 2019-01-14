extern crate bitcoin;
extern crate hex;
extern crate secp256k1;
#[macro_use]
extern crate clap;

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::network::constants::Network;
use bitcoin::network::serialize::{deserialize, serialize};
use bitcoin::util::address::Address;
use bitcoin::Privkey;
use bitcoin::Script;
use bitcoin::Transaction;
use secp256k1::PublicKey;

use std::result::Result;
use std::str::FromStr;
use std::vec::Vec;

use clap::{App, Arg, SubCommand};

/*
//===PASTE THIS INTO C++ CODE====
const string private_key = "cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5";
const uint32_t cltvTimeout = 1523468912;
const int nIn = 0;

// txid = f2a5d4b62c3b44ae43d52a7ccfd287e2c3b3556734df0a0496221bc3a6e545f4
const string rawPrevTxP2SH = "02000000000102790920e76779cc4c4ca0da231db653606c8926e14be40603e8ee8eb0ab913624000000004847304402207d2a141fc25a4406eef2f7617331c872cef3f1e90a1681fd56a7153fa6b374ca02206469fc7a3cdb2c9630e9cac0aa9a74ebe47acf6d0ab7620f1416d8ccf7a2c36c01feffffff94fe814b0ff2eb001e5d90d71a94485491a29ce070dddbedc9696b60b074be3900000000171600143ad9a820efd847c3765d03e2034b4e325a387e3dfeffffff0200f2052a0100000017a91410917b40e26a6a108d6556b4cde6f050b62b68fa873c97f4050000000017a9147af7a6a9bef2fd28ca0c09ccbb12c3d4d3d15f5e870002483045022100f4abec137ae891d6c63a8c2ebb9613f5931431861da15d557b3c93fdaf5a7fd202204faf76411dc7fc3d38fd6c6469476f0285e1f5935244ef1888876d88075f34dd012103a8e3fc99a1ebe9cb050565f8ad381cb06f380e41799a71c29c17cf6cc220a282b9000000";
// to generate rereference spend transaction
// python3 hodl.py -vt cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5 1523468912 spend f2a5d4b62c3b44ae43d52a7ccfd287e2c3b3556734df0a0496221bc3a6e545f4:0 mpvu1CZbTQE9fiJ82b8UxQYTWy1z62eeAA
//===END OF PASTE THIS INTO C++ CODE====
*/

//const SGX_PRIVATE_KEY: &'static str = "cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5";
//const P2SH_TO_BE_SPENT: &'static str = "02000000000102790920e76779cc4c4ca0da231db653606c8926e14be40603e8ee8eb0ab913624000000004847304402207d2a141fc25a4406eef2f7617331c872cef3f1e90a1681fd56a7153fa6b374ca02206469fc7a3cdb2c9630e9cac0aa9a74ebe47acf6d0ab7620f1416d8ccf7a2c36c01feffffff94fe814b0ff2eb001e5d90d71a94485491a29ce070dddbedc9696b60b074be3900000000171600143ad9a820efd847c3765d03e2034b4e325a387e3dfeffffff0200f2052a0100000017a91410917b40e26a6a108d6556b4cde6f050b62b68fa873c97f4050000000017a9147af7a6a9bef2fd28ca0c09ccbb12c3d4d3d15f5e870002483045022100f4abec137ae891d6c63a8c2ebb9613f5931431861da15d557b3c93fdaf5a7fd202204faf76411dc7fc3d38fd6c6469476f0285e1f5935244ef1888876d88075f34dd012103a8e3fc99a1ebe9cb050565f8ad381cb06f380e41799a71c29c17cf6cc220a282b9000000";
//const CLTV_TIMEOUT: u32 = 1523468912;

fn main() {
    let app_matches = App::new("p2sh example")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("network")
                .short("n")
                .long("network")
                .value_name("NETWORK")
                .help("which network to use")
                .possible_values(&["test", "regtest", "main"])
                .default_value("regtest")
                .takes_value(true),
        ).arg(
            Arg::with_name("seckey")
                .required(true)
                .short("s")
                .long("secret")
                .takes_value(true)
                .value_name("SECRET_KEY")
                .help("the private key used to spend a CLTV"),
        ).arg(
            Arg::with_name("locktime")
                .required(true)
                .short("l")
                .long("locktime")
                .value_name("LOCKTIME")
                .help("locktime")
                .takes_value(true),
        ).subcommand(SubCommand::with_name("create").about("create a P2SH address with CLTV"))
        .subcommand(
            SubCommand::with_name("spend")
                .about("spend a time-locked output")
                .args(&[
                    Arg::with_name("transaction_hex")
                        .long("tx")
                        .required(true)
                        .takes_value(true),
                    Arg::with_name("vout").long("vout").default_value("0"),
                    Arg::with_name("target")
                        .long("address")
                        .required(true)
                        .takes_value(true),
                ]),
        ).get_matches();

    let locktime = value_t!(app_matches.value_of("locktime"), u32).expect("locktime arg");
    let secret_key = Privkey::from_str(
        app_matches
            .value_of("seckey")
            .expect("can't find seckey in input"),
    ).expect("can't parse secret key from input");

    let network = match app_matches.value_of("network").expect("network arg") {
        "regtest" => Network::Regtest,
        "test" => Network::Testnet,
        "main" => Network::Bitcoin,
        _ => panic!("can't understand network"),
    };

    // setup logger
    pretty_env_logger::init();

    match app_matches.subcommand() {
        ("create", Some(_)) => {
            let secp = secp256k1::Secp256k1::new();
            let p2sh_address =
                create_cltv_address(locktime, &secret_key.public_key(&secp), network);
            println!("{}", p2sh_address);
            return;
        }
        ("spend", Some(matches)) => {
            let tx_to_spend = deserialize::<Transaction>(
                hex::decode(matches.value_of("transaction_hex").expect("tx_hex arg"))
                    .expect("hex decode")
                    .as_slice(),
            ).expect("deserialize");

            debug!("transaction to be spent: {:?}", tx_to_spend);

            let vout = match value_t!(matches.value_of("vout"), u32) {
                Ok(vout) => vout,
                Err(e) => {
                    error!("{}", e);
                    return;
                }
            };

            let address = match Address::from_str(matches.value_of("target").expect("target arg")) {
                Ok(address) => address,
                Err(e) => {
                    error!("can't get address: {}", e);
                    return;
                }
            };

            let secp = secp256k1::Secp256k1::new();
            let sgx_public_key = secret_key.public_key(&secp);

            let redeem_script = generate_cltv_script(locktime, &sgx_public_key);

            let redeem = RedeemP2SH {
                utxo: &tx_to_spend.output[vout as usize],
                outpoint: &OutPoint {
                    txid: tx_to_spend.txid(),
                    vout,
                },
                redeem_script: &redeem_script,
            };

            let tx_output = TxOut {
                value: redeem.utxo.value - 10000000, // FIXME: a fixed fee is used
                script_pubkey: address.script_pubkey(),
            };

            let tx = match spend_p2sh_utxo_to_p2pkh_address(
                vec![redeem],
                vec![tx_output],
                locktime,
                &secret_key,
            ) {
                Ok(tx) => tx,
                Err(e) => {
                    println!("error: {}", e);
                    return;
                }
            };

            println!("Spending tx is {:#?}", tx);
            println!("serialized: {}", hex::encode(serialize(&tx).unwrap()));

            return;
        }
        _ => {
            println!("{}", app_matches.usage());
            return;
        }
    }

    //    let tx_to_be_spent =
    //        deserialize::<Transaction>(hex::decode(P2SH_TO_BE_SPENT).unwrap().as_slice()).unwrap();
    //
    //    debug!("tx to be spent {:?}", tx_to_be_spent);
    //

    //     spend to a simple p2ph
    //    let to_address = Address::p2pkh(&sgx_public_key, Network::Regtest);
    //    debug!("target P2PKH address {}", to_address);
}

fn create_cltv_address(cltv: u32, public_key: &PublicKey, network: Network) -> Address {
    let redeem_script = generate_cltv_script(cltv, public_key);
    Address::p2sh(&redeem_script, network)
}

/// script: can be spend by public_key after cltv
fn generate_cltv_script(cltv: u32, public_key: &PublicKey) -> Script {
    Builder::new()
        .push_int(cltv as i64)
        .push_opcode(opcodes::OP_CLTV)
        .push_opcode(opcodes::All::OP_DROP)
        .push_slice(public_key.serialize().as_ref())
        .push_opcode(opcodes::All::OP_CHECKSIG)
        .into_script()
}

struct RedeemP2SH<'a> {
    utxo: &'a TxOut,
    outpoint: &'a OutPoint,
    redeem_script: &'a Script,
}

/// build a n to n transaction
fn spend_p2sh_utxo_to_p2pkh_address(
    redeems: Vec<RedeemP2SH>,
    tx_outputs: Vec<TxOut>,
    n_locktime: u32,
    private_key: &Privkey,
) -> Result<Transaction, String> {
    // validate the input
    let mut total_input_value = 0;
    for redeem in redeems.iter() {
        debug!("redeem hash: {}", redeem.redeem_script.to_p2sh());
        if redeem.redeem_script.to_p2sh() != redeem.utxo.script_pubkey {
            debug!("expected script_pubkey: {}", redeem.utxo.script_pubkey);
            return Err("invalid redeem_script".to_string());
        }
        total_input_value += redeem.utxo.value;
    }

    // check for enough fond
    let total_output_value = tx_outputs.iter().fold(0, |v, x| v + x.value);
    if total_input_value < total_output_value {
        return Err("insufficient fund".to_string());
    }

    let tx_inputs: Vec<TxIn> = redeems
        .iter()
        .map(|txin| TxIn {
            previous_output: txin.outpoint.to_owned(),
            script_sig: Script::new(),
            sequence: 0, // FIXME: set to 0xFFFFFFFF will disable cause CLV to fail (https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki/)
            witness: vec![],
        }).collect();

    // build an unsigned tx
    let unsigned_transaction = Transaction {
        version: 1,
        lock_time: n_locktime, // TODO: this is not necessarily the same as the cltv expiration time
        input: tx_inputs,
        output: tx_outputs.clone(),
    };

    let mut final_tx = unsigned_transaction.clone();

    // sign each input
    let secp = secp256k1::Secp256k1::new();
    for i in 0..unsigned_transaction.input.len() {
        // see https://bitcoin.stackexchange.com/questions/66197/step-by-step-example-to-redeem-a-p2sh-output-required
        let hash = unsigned_transaction.signature_hash(i, redeems[i].redeem_script, 0x1);
        let sig = secp
            .sign(
                &match secp256k1::Message::from_slice(hash.as_bytes()) {
                    Ok(m) => m,
                    Err(_) => return Err("sign".to_string()),
                },
                private_key.secret_key(),
            ).serialize_der(&secp);

        debug!("signature length {}", sig.len());
        debug!("signature is {}", hex::encode(&sig));

        // add SIG_HASHALL
        let mut script_sig_first_part = Vec::new();
        script_sig_first_part.extend(sig.iter());
        // why do we need this?

        // https://bitcoin.stackexchange.com/questions/66197/step-by-step-example-to-redeem-a-p2sh-output-required
        script_sig_first_part.push(0x1);

        // attach the signature to script_sig
        let script_sig = Builder::new()
            .push_slice(&script_sig_first_part)
            .push_slice(redeems[i].redeem_script.as_bytes())
            .into_script();

        debug!(
            "script sig {} which is {:?}",
            hex::encode(&script_sig.as_bytes()),
            &script_sig
        );
        final_tx.input[i].script_sig = script_sig;
    }

    Ok(final_tx)
}
