import pytest
from sigma.collection import SigmaCollection
from sigma.backends.signals import SignalsBackend

@pytest.fixture
def signals_backend():
    return SignalsBackend()

def test_signals_and_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ["fieldA='valueA' AND fieldB='valueB'"]

def test_signals_or_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ["fieldA='valueA' OR fieldB='valueB'"]

def test_signals_and_or_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ["(fieldA='valueA1' OR fieldA='valueA2') AND (fieldB='valueB1' OR fieldB='valueB2')"]

def test_signals_or_and_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ["fieldA='valueA1' AND fieldB='valueB1' OR fieldA='valueA2' AND fieldB='valueB2'"]

def test_signals_in_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ["fieldA='valueA' OR fieldA='valueB' OR fieldA starts with 'valueC'"]

def test_signals_regex_query_not_supported(signals_backend: SignalsBackend):
    with pytest.raises(
        NotImplementedError,
        match="Regular expression template is not supported by the backend",
    ):
        signals_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|re: foo.*bar
                        fieldB: foo
                    condition: sel
            """)
        )

def test_signals_cidr_query(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["field starts with '192.168.'"]

def test_signals_field_name_with_whitespace(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['"field\\ name"=\'value\'']

def test_signals_not_contains_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|contains: evil
                filter:
                    CommandLine|contains: good
                condition: sel and not filter
        """)
    ) == [
        "process.command_line contains 'evil' AND process.command_line contains not 'good'"
    ]

def test_signals_not_startswith_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|startswith: foo
                condition: not sel
        """)
    ) == ["field starts with not 'foo'"]

def test_signals_not_endswith_expression(signals_backend: SignalsBackend):
    assert signals_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|endswith: foo
                condition: not sel
        """)
    ) == ["field ends with not 'foo'"]

# NOTE: Expand coverage for custom backend behavior (e.g., deferred expressions) as features are finalized.


