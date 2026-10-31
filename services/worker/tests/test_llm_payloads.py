from worker.llm.payloads import KNOWN_EXPLOIT_PAYLOADS, payloads_for


def test_known_classes_have_three_to_five_payloads():
    for prefix, payloads in KNOWN_EXPLOIT_PAYLOADS.items():
        assert 3 <= len(payloads) <= 5, prefix


def test_payloads_for_matches_by_rule_id_prefix():
    assert payloads_for("routes.sqli.pg-tainted-query") == KNOWN_EXPLOIT_PAYLOADS["routes.sqli"]
    assert payloads_for("routes.xss.reflected-response") == KNOWN_EXPLOIT_PAYLOADS["routes.xss"]


def test_payloads_for_unknown_rule_returns_empty():
    assert payloads_for("routes.crypto.weak-hash") == []
    assert payloads_for("") == []
