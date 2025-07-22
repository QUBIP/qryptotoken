use crate::mldsa::wycheproof::sign_schema::SignSchema;
use crate::mldsa::wycheproof::verify_schema::VerifySchema;
use std::fs::File;
use std::io::BufReader;

pub fn load_verify_schema_from_file<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<VerifySchema, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let schema = serde_json::from_reader(reader)?;
    Ok(schema)
}

pub fn load_sign_schema_from_file<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<SignSchema, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let schema = serde_json::from_reader(reader)?;
    Ok(schema)
}
