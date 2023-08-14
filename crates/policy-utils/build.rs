extern crate lalrpop;

fn main() {
    lalrpop::Configuration::new()
        // .log_debug()
        .use_cargo_dir_conventions()
        // .force_build(true)
        .process()
        .unwrap();
}
