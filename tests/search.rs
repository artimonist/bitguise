#![cfg(test)]
use assert_cmd::Command;

macro_rules! execute {
    ($args:literal) => {{
        let args = $args.split_whitespace().collect::<Vec<_>>();
        let mut cmd = Command::cargo_bin("disguise").unwrap();
        let output = cmd
            .current_dir("tests/search")
            .args(&args)
            .assert()
            .success()
            .get_output()
            .clone();
        String::from_utf8(output.stdout).unwrap()
    }};
}

#[ignore = "removing"]
#[test]
fn test_search() {
    let output = execute!("search youth --target english");
    assert_eq!(output, include_str!("search/youth.out"));

    let output = execute!("search 将进酒 --target ChineseSimplified");
    assert_eq!(output, include_str!("search/将进酒.out"));

    let output = execute!("search 将进酒 --target ChineseTraditional");
    assert_eq!(output, include_str!("search/将进酒.out.1"))
}
