#[macro_use]
extern crate lazy_static;

use rs_yara::*;

const RULES: &str = r#"
rule is_awesome {
  strings:
    $rust = /[Rr]ust/

  condition:
    $rust
}

rule is_ok {
  strings:
    $go = "go"

  condition:
    $go
}"#;

fn main(){
    let mut compiler = Compiler::new().unwrap();
    compiler.add_rules_str(RULES).expect("Should be Ok");
    let rules = compiler.compile_rules().unwrap();

    let result = rules
        .scan_file("tests/scanfile.txt", 10)
        .expect("Should have scanned file");
    assert_eq!(1, result.len());

    


}