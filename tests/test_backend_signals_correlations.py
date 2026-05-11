import pytest
from sigma.collection import SigmaCollection
from sigma.backends.signals import SignalsBackend


@pytest.fixture
def signals_backend() -> SignalsBackend:
    return SignalsBackend()

# Correlation query coverage for backends that support Sigma correlation rules.
def test_event_count_correlation_rule_stats_query(signals_backend: SignalsBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert signals_backend.convert(correlation_rule) == [
        """fieldA='value1' AND fieldB='value2'
| aggregate window=15min count() as event_count by fieldC, fieldD
| where event_count >= 10"""
    ]

def test_value_count_correlation_rule_stats_query(signals_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: fieldD
            """
    )
    assert signals_backend.convert(correlation_rule) == [
        """fieldA='value1' AND fieldB='value2'
| aggregate window=15min value_count(fieldD) as value_count by fieldC
| where value_count < 10"""
    ]

def test_temporal_correlation_rule_stats_query(signals_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    aliases:
        field:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert signals_backend.convert(correlation_rule) == [
        """subsearch (( fieldA='value1' AND fieldB='value2' | set event_type="base_rule_1" | set field=fieldC ))
subsearch (( fieldA='value3' AND fieldB='value4' | set event_type="base_rule_2" | set field=fieldD ))

| temporal window=15min eventtypes=base_rule_1,base_rule_2 by fieldC

| where eventtype_count >= 2"""
    ]

def test_temporal_ordered_correlation_rule_stats_query(signals_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Ordered temporal correlation rule
status: test
correlation:
    type: temporal_ordered
    rules:
        - base_rule_1
        - base_rule_2
    aliases:
        field:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert signals_backend.convert(correlation_rule) == [
        """subsearch (( fieldA='value1' AND fieldB='value2' | set event_type="base_rule_1" | set field=fieldC ))
subsearch (( fieldA='value3' AND fieldB='value4' | set event_type="base_rule_2" | set field=fieldD ))
| temporal ordered=true window=15min eventtypes=base_rule_1,base_rule_2 by fieldC
| where eventtype_count >= 2 and eventtype_order=base_rule_1,base_rule_2"""
    ]