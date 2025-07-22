use serde::{Deserialize, Serialize};
#[derive(PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySchema {
    pub algorithm: String,

    pub generator_version: String,

    pub header: Vec<String>,

    pub notes: Notes,

    pub number_of_tests: i64,

    pub schema: String,

    pub test_groups: Vec<TestGroup>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Notes {
    pub boundary_condition: BoundaryCondition,

    pub incorrect_public_key_length: BoundaryCondition,

    pub incorrect_signature_length: BoundaryCondition,

    pub invalid_hints_encoding: BoundaryCondition,

    pub invalid_private_key: BoundaryCondition,

    pub many_steps: BoundaryCondition,

    pub modified_signature: BoundaryCondition,

    pub valid_signature: BoundaryCondition,

    pub zero_public_key: BoundaryCondition,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryCondition {
    pub bug_type: String,

    pub description: String,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup {
    #[serde(rename = "type")]
    pub test_group_type: Type,

    pub public_key: String,

    pub tests: Vec<Test>,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub enum Type {
    #[serde(rename = "MlDsaVerify")]
    MlDsaVerify,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Test {
    pub tc_id: i64,

    pub comment: String,

    pub msg: String,

    #[serde(default)]
    pub ctx: String,

    pub sig: String,

    pub result: VerifyResult,

    pub flags: Vec<Flag>,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub enum Flag {
    #[serde(rename = "BoundaryCondition")]
    BoundaryCondition,

    #[serde(rename = "IncorrectPublicKeyLength")]
    IncorrectPublicKeyLength,

    #[serde(rename = "IncorrectSignatureLength")]
    IncorrectSignatureLength,

    #[serde(rename = "InvalidHintsEncoding")]
    InvalidHintsEncoding,

    #[serde(rename = "InvalidPrivateKey")]
    InvalidPrivateKey,

    #[serde(rename = "InvalidContext")]
    InvalidContext,

    #[serde(rename = "ManySteps")]
    ManySteps,

    #[serde(rename = "ModifiedSignature")]
    ModifiedSignature,

    #[serde(rename = "ValidSignature")]
    ValidSignature,

    #[serde(rename = "ZeroPublicKey")]
    ZeroPublicKey,
}

#[derive(PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum VerifyResult {
    Invalid,

    Valid,
}
