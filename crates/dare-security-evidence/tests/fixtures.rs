mod common;

use dare_security_evidence::Verdict;

#[test]
fn pass_fixture_validates() {
    common::assert_fixture("pass.json", Verdict::Pass);
}

#[test]
fn fail_fixture_validates() {
    common::assert_fixture("fail.json", Verdict::Fail);
}

#[test]
fn inconclusive_fixture_validates() {
    common::assert_fixture("inconclusive.json", Verdict::Inconclusive);
}

#[test]
fn error_fixture_validates() {
    common::assert_fixture("error.json", Verdict::Error);
}
