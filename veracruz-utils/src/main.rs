use veracruz_utils::policy::{VeracruzPolicy, VeracruzCapabilityIndex, VeracruzCapability};
use std::fs;

fn main() {
    let contents = fs::read_to_string("../test-collateral/one_data_source_policy.json")
                                    .expect("Something went wrong reading the file");
    let policy = VeracruzPolicy::from_json(contents.as_str()).unwrap();
    println!("raw: {:?}", policy);
    println!("capabilities: {:?}", policy.get_capability_table());
    println!("program: {:?}", policy.get_program_digests());
    let capabilities = policy.get_capability_table();
    let rst = capabilities
            .get(&VeracruzCapabilityIndex::Principal(0))
            .unwrap()
            .get("input-0")
            .unwrap()
            .contains(&VeracruzCapability::Write);
    println!("{:?}",rst);
}
