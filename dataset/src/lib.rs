use std::fmt;
use std::path::Path;

use serde::Deserialize;

pub mod decomposition;
pub use decomposition::Enabled;

pub const SCHEMA_VERSION: u32 = 4;

pub const TRAVERSAL_COUNT: usize = 1 + SORT_KEY_NAMES.len();

pub const SORT_KEY_NAMES: [&str; 2] = ["key1", "key2"];
pub const FIELDS_PER_RECORD: usize = 8;

pub const FIELD_NAMES: [&str; FIELDS_PER_RECORD] = [
    "record_id",
    "active",
    "vehicle_id",
    "start",
    "end",
    "origin_hub",
    "destination_hub",
    "load_kg",
];

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for Error {}

fn fail<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error(message.into()))
}

#[derive(Clone, Debug, Deserialize)]
pub struct RangeCheckBits {
    pub record_id: usize,
    pub vehicle_id: usize,
    pub start: usize,
    pub end: usize,
    pub origin_hub: usize,
    pub destination_hub: usize,
    pub load_kg: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Constants {
    pub time_minimum: u64,
    pub time_maximum: u64,
    pub allowed_hubs: Vec<u64>,
    pub positive_load_ratio_numerator: u64,
    pub positive_load_ratio_denominator: u64,

    pub count_bits: usize,
    pub range_check_bits: RangeCheckBits,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Challenges {
    pub fingerprint_challenge: String,
    pub grand_product_challenge: String,
    pub record_stride: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Blinding {
    pub grand_product_element: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Expected {
    pub fingerprint: String,
    pub grand_product_presented: String,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub record_id: String,
    pub active: bool,
    pub vehicle_id: u64,
    pub start: u64,
    pub end: u64,
    pub origin_hub: u64,
    pub destination_hub: u64,
    pub load_kg: u64,
}

#[derive(Deserialize)]
struct Document {
    schema_version: u32,
    variant: String,
    record_count: usize,
    row_count: usize,
    records_per_vehicle: usize,
    seed: u64,
    blinding_seed: u64,
    target_predicate: Option<String>,
    field_names: Vec<String>,
    constants: Constants,
    presented_records: Vec<Vec<String>>,
    permutation_to_key1: Vec<usize>,
    permutation_to_key2: Vec<usize>,
    transcript_commitment: String,
    challenges: Challenges,
    blinding: Blinding,
    expected: Expected,
}

#[derive(Clone, Debug)]
pub struct Dataset {
    pub variant: String,
    pub record_count: usize,
    pub records_per_vehicle: usize,
    pub seed: u64,
    pub blinding_seed: u64,
    pub target_predicate: Option<String>,
    pub constants: Constants,
    pub presented_records: Vec<Row>,
    pub permutation_to_key1: Vec<usize>,
    pub permutation_to_key2: Vec<usize>,

    pub transcript_commitment: String,
    pub challenges: Challenges,
    pub blinding: Blinding,
    pub expected: Expected,
}

impl Dataset {
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|error| Error(format!("{}: {error}", path.display())))?;
        let document: Document = serde_json::from_str(&text)
            .map_err(|error| Error(format!("{}: {error}", path.display())))?;
        Self::from_document(document)
    }

    fn from_document(document: Document) -> Result<Self, Error> {
        if document.schema_version != SCHEMA_VERSION {
            return fail(format!(
                "unsupported schema_version {}, this build reads {SCHEMA_VERSION}",
                document.schema_version
            ));
        }
        if document.field_names != FIELD_NAMES {
            return fail(format!(
                "field order changed: file has {:?}, this build has {FIELD_NAMES:?}",
                document.field_names
            ));
        }
        if document.presented_records.len() != document.row_count {
            return fail(format!(
                "row_count is {} but {} rows are present",
                document.row_count,
                document.presented_records.len()
            ));
        }
        if document.record_count + 1 != document.row_count {
            return fail(format!(
                "row_count {} is not record_count {} plus the blinder row",
                document.row_count, document.record_count
            ));
        }

        let presented_records = document
            .presented_records
            .iter()
            .enumerate()
            .map(|(index, values)| parse_row(index, values))
            .collect::<Result<Vec<Row>, Error>>()?;

        for (name, permutation) in [
            ("permutation_to_key1", &document.permutation_to_key1),
            ("permutation_to_key2", &document.permutation_to_key2),
        ] {
            if permutation.len() != document.row_count {
                return fail(format!(
                    "{name} has {} entries, expected {}",
                    permutation.len(),
                    document.row_count
                ));
            }
            if let Some(out_of_range) = permutation.iter().find(|&&index| index >= document.row_count)
            {
                return fail(format!("{name} contains out-of-range position {out_of_range}"));
            }
        }

        Ok(Self {
            variant: document.variant,
            record_count: document.record_count,
            records_per_vehicle: document.records_per_vehicle,
            seed: document.seed,
            blinding_seed: document.blinding_seed,
            target_predicate: document.target_predicate,
            constants: document.constants,
            presented_records,
            permutation_to_key1: document.permutation_to_key1,
            permutation_to_key2: document.permutation_to_key2,
            transcript_commitment: document.transcript_commitment,
            challenges: document.challenges,
            blinding: document.blinding,
            expected: document.expected,
        })
    }

    pub fn row_count(&self) -> usize {
        self.presented_records.len()
    }

    pub fn traversals(&self) -> Result<Vec<Vec<Row>>, Error> {
        let mut traversals = vec![self.presented_records.clone()];
        for name in SORT_KEY_NAMES {
            traversals.push(self.view(name)?);
        }
        Ok(traversals)
    }

    pub fn view(&self, sort_key_name: &str) -> Result<Vec<Row>, Error> {
        let permutation = match sort_key_name {
            "key1" => &self.permutation_to_key1,
            "key2" => &self.permutation_to_key2,
            other => return fail(format!("unknown sort key {other:?}")),
        };
        Ok(permutation
            .iter()
            .map(|&position| self.presented_records[position].clone())
            .collect())
    }
}

fn parse_row(index: usize, values: &[String]) -> Result<Row, Error> {
    if values.len() != FIELDS_PER_RECORD {
        return fail(format!("row {index} has {} values, expected {FIELDS_PER_RECORD}", values.len()));
    }
    let small = |position: usize| -> Result<u64, Error> {
        values[position].parse::<u64>().map_err(|error| {
            Error(format!(
                "row {index} field {}: {error}",
                FIELD_NAMES[position]
            ))
        })
    };
    let active = match values[1].as_str() {
        "0" => false,
        "1" => true,
        other => return fail(format!("row {index} field active is {other:?}, expected 0 or 1")),
    };
    Ok(Row {
        record_id: values[0].clone(),
        active,
        vehicle_id: small(2)?,
        start: small(3)?,
        end: small(4)?,
        origin_hub: small(5)?,
        destination_hub: small(6)?,
        load_kg: small(7)?,
    })
}
