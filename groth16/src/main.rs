use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::str::FromStr;

use ark_ff::{BigInteger, PrimeField};
use dataset::Dataset;
use groth16::commitment::FIELDS_PER_RECORD;
use groth16::{fingerprint_of, DataQualityCircuit, PreparedRow};

const SETUP_SEED: u64 = 0xDA7A_C0DE;

fn parse_hex_or_exit(label: &str, text: &str) -> Fr {
    let digits = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    let padded = format!("{digits:0>64}");
    let mut big_endian = [0u8; 32];
    for index in 0..32 {
        big_endian[index] = match u8::from_str_radix(&padded[2 * index..2 * index + 2], 16) {
            Ok(byte) => byte,
            Err(error) => {
                eprintln!("groth16: {label}: {text:?}: {error}");
                std::process::exit(2);
            }
        };
    }
    Fr::from_be_bytes_mod_order(&big_endian)
}

fn to_hex(element: &Fr) -> String {
    let mut text = String::from("0x");
    for byte in element.into_bigint().to_bytes_be() {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let path = match arguments.next() {
        Some(path) => path,
        None => {
            eprintln!(
                "usage: groth16 <dataset.json> [claimed_commitment_decimal] [--all-pairs] \
                 [--enable=p1,p2,...]"
            );
            std::process::exit(2);
        }
    };

    let remaining: Vec<String> = arguments.collect();
    let all_pairs = remaining.iter().any(|argument| argument == "--all-pairs");

    let enabled = dataset::Enabled::from_arguments(remaining.iter()).unwrap_or_else(|error| {
        eprintln!("groth16: {error}");
        std::process::exit(2);
    });
    let claimed_commitment = remaining
        .iter()
        .find(|argument| !argument.starts_with("--"))
        .cloned();

    let dataset = Dataset::read(&path).unwrap_or_else(|error| {
        eprintln!("groth16: {error}");
        std::process::exit(2);
    });
    let rows = PreparedRow::prepare_all(&dataset.presented_records).unwrap_or_else(|error| {
        eprintln!("groth16: {error}");
        std::process::exit(2);
    });

    let claimed_view = |key: &str| {
        dataset
            .view(key)
            .map_err(|error| error.to_string())
            .and_then(|view| PreparedRow::prepare_all(&view))
            .unwrap_or_else(|error| {
                eprintln!("groth16: {error}");
                std::process::exit(2);
            })
    };
    let sorted_by_vehicle_and_start = claimed_view("key1");
    let sorted_by_record_id = claimed_view("key2");
    let row_count = rows.len();

    let published_commitment = match &claimed_commitment {
        Some(text) => Fr::from_str(text).unwrap_or_else(|_| {
            eprintln!("groth16: {text:?} is not a field element");
            std::process::exit(2);
        }),

        None => {
            let elements = |view: &[PreparedRow]| {
                view.iter().map(PreparedRow::field_elements).collect::<Vec<_>>()
            };
            let absent = vec![[Fr::from(0u64); FIELDS_PER_RECORD]; row_count];
            let mut lanes = vec![elements(&rows)];

            if !all_pairs {
                lanes.push(if enabled.sigma1() {
                    elements(&sorted_by_vehicle_and_start)
                } else {
                    absent.clone()
                });
                lanes.push(if enabled.sigma2() {
                    elements(&sorted_by_record_id)
                } else {
                    absent
                });
            }
            groth16::commitment::commitment(&lanes)
        }
    };

    let fingerprint_challenge = parse_hex_or_exit(
        "fingerprint_challenge",
        &dataset.challenges.fingerprint_challenge,
    );
    let expected_fingerprint =
        parse_hex_or_exit("expected.fingerprint", &dataset.expected.fingerprint);
    let native_fingerprint = fingerprint_of(&rows, fingerprint_challenge);
    let grand_product_challenge = parse_hex_or_exit(
        "grand_product_challenge",
        &dataset.challenges.grand_product_challenge,
    );

    let grand_product_blinding_element = parse_hex_or_exit(
        "blinding.grand_product_element",
        &dataset.blinding.grand_product_element,
    );
    let circuit = DataQualityCircuit {
        rows,
        constants: dataset.constants.clone(),
        published_commitment,
        fingerprint_challenge,
        expected_fingerprint,
        sorted_by_vehicle_and_start,
        sorted_by_record_id,
        grand_product_challenge,
        grand_product_blinding_element,
        all_pairs,
        enabled,
    };

    let started = Instant::now();
    let constraint_system = ConstraintSystem::<Fr>::new_ref();
    circuit
        .clone()
        .generate_constraints(constraint_system.clone())
        .expect("synthesis");
    let satisfied = constraint_system.is_satisfied().expect("satisfiability");
    let synthesis_seconds = started.elapsed().as_secs_f64();
    let constraints = constraint_system.num_constraints();

    eprintln!(
        "[groth16] variant={} rows={row_count} constraints={constraints} satisfied={satisfied}",
        dataset.variant
    );

    let mut setup_seconds = 0.0;
    let mut proof_seconds = 0.0;
    let mut verify_seconds = 0.0;
    let mut proof_bytes = 0;
    let mut verified = false;

    if satisfied {
        let mut rng = StdRng::seed_from_u64(SETUP_SEED);

        let started = Instant::now();
        let (proving_key, verifying_key) =
            Groth16::<Bn254>::setup(circuit.clone(), &mut rng).expect("setup");
        setup_seconds = started.elapsed().as_secs_f64();
        let prepared_verifying_key = prepare_verifying_key(&verifying_key);

        let started = Instant::now();
        let proof = Groth16::<Bn254>::prove(&proving_key, circuit, &mut rng).expect("prove");
        proof_seconds = started.elapsed().as_secs_f64();
        proof_bytes = proof.serialized_size(Compress::Yes);

            let started = Instant::now();
        verified = Groth16::<Bn254>::verify_with_processed_vk(
            &prepared_verifying_key,
            &[
                published_commitment,
                fingerprint_challenge,
                expected_fingerprint,
                grand_product_challenge,
            ],
            &proof,
        )
        .expect("verify");
        verify_seconds = started.elapsed().as_secs_f64();

        eprintln!(
            "[groth16] setup {setup_seconds:.3}s proof {proof_seconds:.3}s \
             verify {verify_seconds:.3}s verified={verified}"
        );
    } else {
        eprintln!("[groth16] unsatisfied, so no proof exists; skipping setup and proving");
    }

    let opened_commitment = if satisfied {
        to_hex(&published_commitment)
    } else {
        String::from("0x0")
    };

    let public_input_count = 4;
    let opened_fingerprint = if satisfied {
        to_hex(&native_fingerprint)
    } else {
        String::from("0x0")
    };
    let rung = if all_pairs { "S2-prime" } else { "S2" };

    println!(
        "{{\"backend\":\"groth16\",\"rung\":\"{rung}\",\"enabled\":\"{}\",\"variant\":\"{}\",\
         \"record_count\":{},\"row_count\":{row_count},\
         \"satisfied\":{satisfied},\"verified\":{verified},\
         \"constraint_unit\":\"r1cs_constraints_whole_circuit\",\"constraints\":{constraints},\
         \"commitment\":\"{opened_commitment}\",\"published_commitment\":\"{}\",\
         \"fingerprint\":\"{opened_fingerprint}\",\"expected_fingerprint\":\"{}\",\
         \"public_input_count\":{public_input_count},\
         \"grand_product\":null,\"expected_grand_product\":\"{}\",\
         \"phases\":{{\"synthesis\":{synthesis_seconds},\"setup\":{setup_seconds},\
         \"proof\":{proof_seconds},\"verify\":{verify_seconds}}},\
         \"proof_bytes\":{proof_bytes}}}",
        enabled.to_list(),
        dataset.variant,
        dataset.record_count,
        to_hex(&published_commitment),
        to_hex(&expected_fingerprint),
        dataset.expected.grand_product_presented
    );
}
