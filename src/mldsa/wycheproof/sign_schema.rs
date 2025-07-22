use serde::{Deserialize, Serialize};

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignSchema {
    pub algorithm: String,

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

    pub incorrect_private_key_length: BoundaryCondition,

    pub invalid_private_key: BoundaryCondition,

    pub many_steps: BoundaryCondition,
    pub valid_signature: BoundaryCondition,
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

    #[serde(alias = "privateKey", alias = "privateSeed")]
    pub private_input: String,

    pub source: Source,

    pub tests: Vec<Test>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub name: String,
    pub version: String,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub enum Type {
    #[serde(rename = "MlDsaSign")]
    MlDsaSign,
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

    pub result: SignResult,

    pub flags: Vec<Flag>,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub enum Flag {
    #[serde(rename = "BoundaryCondition")]
    BoundaryCondition,

    #[serde(rename = "IncorrectPrivateKeyLength")]
    IncorrectPrivateKeyLength,

    #[serde(rename = "InvalidPrivateKey")]
    InvalidPrivateKey,

    #[serde(rename = "InvalidContext")]
    InvalidContext,

    #[serde(rename = "ManySteps")]
    ManySteps,

    #[serde(rename = "ValidSignature")]
    ValidSignature,
}

#[derive(PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SignResult {
    Invalid,

    Valid,
}
