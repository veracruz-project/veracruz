use veracruz_utils::policy::{VeracruzPolicy, VeracruzCapabilityIndex, VeracruzCapability};
use std::fs;

fn main() {
    let contents = fs::read_to_string("../test-collateral/two_data_source_string_edit_distance_policy.json")
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
    let digests = policy.get_program_digests();
    println!("{:?}",digests);
    //let rst = hex::decode(digests
            //.get("string-edit-distance.wasm")
            //.unwrap()).unwrap();
    //println!("{:?}",rst);
}
