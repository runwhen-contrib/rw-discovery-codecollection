from __future__ import annotations

import jmespath

from rwdiscovery.jsonpath_jmespath import jsonpath_to_jmespath


def test_simple_dotted_path():
    assert jsonpath_to_jmespath(".status.phase") == "status.phase"


def test_root_path():
    assert jsonpath_to_jmespath(".") == "@"


def test_array_index_passes_through():
    assert jsonpath_to_jmespath(".spec.rules[0].host") == "spec.rules[0].host"


def test_filter_expression_strips_at_dot_and_requotes_string_literal():
    converted = jsonpath_to_jmespath('.status.conditions[?(@.type=="Ready")].status')
    assert converted == "status.conditions[?type=='Ready'].status"
    # and it must actually compile and evaluate under jmespath
    doc = {"status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    assert jmespath.compile(converted).search(doc) == ["True"]


def test_filter_expression_compiles_when_run_against_jmespath_directly():
    converted = jsonpath_to_jmespath(".status.conditions[?(@.type=='Ready')].status")
    jmespath.compile(converted)  # must not raise


def test_common_crd_printer_columns_all_compile():
    """A representative sample of real additionalPrinterColumns JSONPaths
    (cert-manager Certificate, Gateway API HTTPRoute) -- every one must
    both convert and compile."""
    samples = [
        '.status.conditions[?(@.type=="Ready")].status',
        ".spec.secretName",
        ".status.notAfter",
        ".metadata.creationTimestamp",
        ".spec.parentRefs[0].name",
    ]
    for sample in samples:
        jmespath.compile(jsonpath_to_jmespath(sample))
