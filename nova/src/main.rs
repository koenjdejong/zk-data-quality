use std::time::Instant;

use dataset::Dataset;
use nova::commitment;
use nova::step::{initial_state, steps_from_views_enforcing, MergedConstants, PreparedRow};
use nova::{
    audit, field_element_from_decimal, field_element_from_hex, field_element_to_hex,
    public_state_carries_counters, public_state_carries_the_grand_product,
    PublishedClaim, POLYNOMIAL_COMMITMENT,
};

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("nova: {message}");
    std::process::exit(2)
}

fn parse_hex_or_exit(label: &str, text: &str) -> nova::Fr {
    field_element_from_hex(text).unwrap_or_else(|error| fail(format!("{label}: {error}")))
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    if arguments.iter().any(|argument| argument == "--all-pairs") {
        fail(concat!(
            "--all-pairs needs a step circuit whose arity grows with the record count, ",
            "which no folding backend can express"
        ));
    }

    let enabled =
        dataset::Enabled::from_arguments(arguments.iter()).unwrap_or_else(|error| fail(error));
    let mut positional = arguments.iter().filter(|argument| !argument.starts_with("--"));
    let path = match positional.next() {
        Some(path) => path.clone(),
        None => fail(
            "usage: nova <dataset.json> [claimed_commitment_decimal] \
             [--enable=p1,p2,...]",
        ),
    };

    let claimed_commitment = positional.next().cloned();

    let dataset = Dataset::read(&path).unwrap_or_else(|error| fail(error));
    let constants = MergedConstants::from_dataset(&dataset.constants);

    let anchor_rows =
        PreparedRow::prepare_all(&dataset.presented_records).unwrap_or_else(|error| fail(error));
    let mut view_rows = Vec::new();
    for name in ["key1", "key2"] {
        let view = dataset
            .view(name)
            .map_err(|error| error.to_string())
            .and_then(|view| PreparedRow::prepare_all(&view))
            .unwrap_or_else(|error| fail(error));
        view_rows.push(view);
    }
    let key2_rows = view_rows.pop().expect("key2");
    let key1_rows = view_rows.pop().expect("key1");

    let absent_lane: Vec<[nova::Fr; commitment::FIELDS_PER_RECORD]> =
        vec![[nova::Fr::from(0u64); commitment::FIELDS_PER_RECORD]; anchor_rows.len()];
    let lane_of = |rows: &[PreparedRow], carried: bool| {
        if carried {
            rows.iter().map(PreparedRow::field_elements).collect::<Vec<_>>()
        } else {
            absent_lane.clone()
        }
    };
    let published_commitment = match &claimed_commitment {
        Some(text) => field_element_from_decimal(text).unwrap_or_else(|error| fail(error)),
        None => commitment::tuple_commitment(&[
            anchor_rows.iter().map(PreparedRow::field_elements).collect::<Vec<_>>(),
            lane_of(&key1_rows, enabled.sigma1()),
            lane_of(&key2_rows, enabled.sigma2()),
        ]),
    };

    let fingerprint_challenge =
        parse_hex_or_exit("fingerprint_challenge", &dataset.challenges.fingerprint_challenge);
    let expected_stride = parse_hex_or_exit("record_stride", &dataset.challenges.record_stride);
    let expected_fingerprint =
        parse_hex_or_exit("expected.fingerprint", &dataset.expected.fingerprint);
    let grand_product_challenge = parse_hex_or_exit(
        "grand_product_challenge",
        &dataset.challenges.grand_product_challenge,
    );
    if nova::rlc::record_stride(fingerprint_challenge) != expected_stride {
        fail("the file's record_stride is not fingerprint_challenge^8");
    }

    let pad = parse_hex_or_exit(
        "blinding.grand_product_element",
        &dataset.blinding.grand_product_element,
    );

    let steps = steps_from_views_enforcing(anchor_rows, key1_rows, key2_rows, pad, &constants, enabled)
        .unwrap_or_else(|error| fail(error));
    let row_count = steps.len();
    let state = initial_state(
        fingerprint_challenge,
        expected_stride,
        grand_product_challenge,
        row_count,
    );

    let step_constraints = nova::step_constraint_count(&steps[0], &state);

    let started = Instant::now();
    let simulated = nova::simulate(&steps, &state);
    let satisfied = simulated.is_ok();
    let synthesis_seconds = started.elapsed().as_secs_f64();

    eprintln!(
        "[nova] variant={} rows={row_count} rows_per_step=3 \
         commitment={POLYNOMIAL_COMMITMENT} step_constraints={step_constraints} \
         satisfied={satisfied}",
        dataset.variant
    );
    let mut failed_constraint = String::from("null");
    if let Err(unsatisfied) = &simulated {
        eprintln!(
            "[nova] step {} has no witness, so no proof exists; the constraint it \
             broke is {:?}",
            unsatisfied.index, unsatisfied.constraint
        );
        failed_constraint = format!("{:?}", unsatisfied.constraint);
    }

    let mut setup_seconds = 0.0;
    let mut fold_seconds = 0.0;
    let mut compress_seconds = 0.0;
    let mut verify_seconds = 0.0;
    let mut proof_bytes = 0;
    let mut verified = false;
    let mut opened_commitment = String::from("0x0");
    let mut opened_fingerprint = String::from("0x0");
    let mut carries_counters = false;
    let mut carries_grand_product = false;

    if satisfied {
        let started = Instant::now();
        let parameters = nova::setup(&steps[0]);
        setup_seconds = started.elapsed().as_secs_f64();

        let started = Instant::now();
        let folded = nova::fold(&parameters, &steps, &state).unwrap_or_else(|error| {
            eprintln!("nova: {error}");
            std::process::exit(1);
        });
        fold_seconds = started.elapsed().as_secs_f64();

        let started = Instant::now();
        let (verifier_key, compressed) =
            nova::compress(&parameters, &folded).unwrap_or_else(|error| {
                eprintln!("nova: {error}");
                std::process::exit(1);
            });
        compress_seconds = started.elapsed().as_secs_f64();
        proof_bytes = bincode::serialize(&compressed).map(|bytes| bytes.len()).unwrap_or(0);

        let claim = PublishedClaim {
            row_count,
            initial_state: state.clone(),
            fingerprint_challenge,
            grand_product_challenge,
            commitment: published_commitment,
            fingerprint: expected_fingerprint,
            enabled,
        };
        let started = Instant::now();
        let audited = audit(&verifier_key, &compressed, &claim);
        verify_seconds = started.elapsed().as_secs_f64();

        match audited {
            Ok(final_state) => {
                verified = true;
                opened_commitment = field_element_to_hex(&final_state[nova::step::SLOT_COMMITMENT_CHAIN]);
                opened_fingerprint = field_element_to_hex(&final_state[nova::step::SLOT_FINGERPRINT]);
                carries_counters = public_state_carries_counters(&final_state);
                carries_grand_product =
                    public_state_carries_the_grand_product(&final_state);
            }
            Err(error) => eprintln!("[nova] the audit failed: {error}"),
        }

        eprintln!(
            "[nova] setup {setup_seconds:.3}s fold {fold_seconds:.3}s \
             compress {compress_seconds:.3}s verify {verify_seconds:.4}s verified={verified}"
        );
    }

    println!(
        "{{\"backend\":\"nova\",\"rung\":\"S2\",\"enabled\":\"{}\",\"variant\":\"{}\",\
         \"record_count\":{},\"row_count\":{row_count},\"rows_per_step\":3,\
         \"polynomial_commitment\":\"{POLYNOMIAL_COMMITMENT}\",\
         \"satisfied\":{satisfied},\"verified\":{verified},\
         \"constraint_unit\":\"r1cs_constraints_step_circuit\",\
         \"step_constraints\":{step_constraints},\
         \"commitment\":\"{opened_commitment}\",\"published_commitment\":\"{}\",\
         \"fingerprint\":\"{opened_fingerprint}\",\"expected_fingerprint\":\"{}\",\
         \"public_state_carries_counters\":{carries_counters},\
         \"public_state_carries_the_grand_product\":{carries_grand_product},\
         \"public_input_count\":{},\
         \"grand_product\":null,\"expected_grand_product\":\"{}\",\
         \"failed_constraint\":{failed_constraint},\
         \"phases\":{{\"synthesis\":{synthesis_seconds},\"setup\":{setup_seconds},\
         \"fold\":{fold_seconds},\"compress\":{compress_seconds},\"verify\":{verify_seconds}}},\
         \"proof_bytes\":{proof_bytes}}}",
        enabled.to_list(),
        dataset.variant,
        dataset.record_count,
        field_element_to_hex(&published_commitment),
        field_element_to_hex(&expected_fingerprint),
        state.len(),
        dataset.expected.grand_product_presented
    );
}
