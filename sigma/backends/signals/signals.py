import json
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.correlations import SigmaCorrelationRule
from sigma.pipelines.signals import signals_pipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaRegularExpressionFlag
import re
from typing import Any, ClassVar, Dict, List, Optional, Pattern, Tuple, Union

# Future backend imports you may enable later:
# from sigma.conversion.state import ConversionState
# from sigma.rule import SigmaRule
# from sigma.types import SigmaRegularExpression

class SignalsBackend(TextQueryBackend):
    """Signals backend."""

    name: ClassVar[str] = "signals backend"
    formats: Dict[str, str] = {
        "default": "Plain signals queries",
        "json": "JSON output with query and Sigma metadata",
    }
    requires_pipeline: ClassVar[bool] = True
    backend_processing_pipeline = signals_pipeline()

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"

    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^[A-Za-z0-9_.]+$")
    field_quote_pattern_negation: ClassVar[bool] = True

    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = True
    field_escape_pattern: ClassVar[Pattern] = re.compile(r"\s")

    str_quote: ClassVar[str] = "'"
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    startswith_expression: ClassVar[str] = "{field} starts with {value}"
    endswith_expression: ClassVar[str] = "{field} ends with {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression: ClassVar[str] = "{field} matches {value}"

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = "{field} matches regex {regex}"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str, ...]] = ()
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = True
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE: "m",
        SigmaRegularExpressionFlag.DOTALL: "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression: ClassVar[str] = "{field} = {value}"
    case_sensitive_startswith_expression: ClassVar[str] = "{field} starts with {value}"
    case_sensitive_endswith_expression: ClassVar[str] = "{field} ends with {value}"
    case_sensitive_contains_expression: ClassVar[str] = "{field} contains {value}"

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression: ClassVar[Optional[str]] = None

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[Optional[str]] = None
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)

    # Null/None expressions
    field_null_expression: ClassVar[str] = "{field} is null"

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str] = "{field} exists"
    field_not_exists_expression: ClassVar[str] = "{field} not exists"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = False
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "in"
    and_in_operator: ClassVar[str] = "in"
    list_separator: ClassVar[str] = ", "

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = "{value}"
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = "\n| "
    deferred_separator: ClassVar[str] = "\n| "
    deferred_only_query: ClassVar[str] = "*"

    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Test correlation method",
    }
    default_correlation_method: ClassVar[str] = "default"
    default_correlation_query: ClassVar[str] = {"default": "{search}\n{aggregate}\n{condition}"}
    temporal_correlation_query: ClassVar[str] = {"default": "{search}\n\n{aggregate}\n\n{condition}"}

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[
        str
    ] = 'subsearch (( {query} | set event_type="{ruleid}"{normalization} ))'
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = "\n"

    correlation_search_field_normalization_expression: ClassVar[str] = " | set {alias}={field}"
    correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| aggregate window={timespan} count() as event_count{groupby}"
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| aggregate window={timespan} value_count({field}) as value_count{groupby}"
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| temporal window={timespan} eventtypes={referenced_rules}{groupby}"
    }
    temporal_ordered_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| temporal ordered=true window={timespan} eventtypes={referenced_rules}{groupby}"
    }

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "m": "min",
    }
    referenced_rules_expression: ClassVar[Dict[str, str]] = {"default": "{ruleid}"}
    referenced_rules_expression_joiner: ClassVar[Dict[str, str]] = {"default": ","}

    groupby_expression: ClassVar[Dict[str, str]] = {"default": " by {fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": ", "}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where event_count {op} {count}"
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where value_count {op} {count}"
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where eventtype_count {op} {count}"
    }
    temporal_ordered_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "| where eventtype_count {op} {count} and eventtype_order={referenced_rules}"
    }
    ### Correlation end ###

    @staticmethod
    def _extract_mitre_technique_ids(rule: SigmaRule) -> List[str]:
        technique_ids: List[str] = []
        for tag in rule.tags or []:
            tag_value = str(tag).lower()
            if not tag_value.startswith("attack.t"):
                continue
            technique_id = tag_value.split(".", 1)[1].upper()
            technique_ids.append(technique_id)
        return technique_ids

    def finalize_query_json(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: str,
        index: int,
        state: ConversionState,
    ) -> Dict[str, Any]:
        if isinstance(rule, SigmaCorrelationRule):
            return {
                "name": rule.name or "",
                "text": query,
                "platforms": [],
                "syntax_version": "",
                "mitreAttack": {"technique_ids": []},
            }

        platforms: List[str] = []
        if rule.logsource is not None:
            for value in (rule.logsource.product, rule.logsource.service):
                if value:
                    platforms.append(value)

        return {
            "name": rule.title or "",
            "text": query,
            "platforms": platforms,
            "syntax_version": str(getattr(rule, "sigma_version", "") or ""),
            "mitreAttack": {
                "technique_ids": self._extract_mitre_technique_ids(rule),
            },
        }

    def finalize_output_json(self, queries: List[Dict[str, Any]]) -> str:
        return json.dumps(queries, indent=2)


# Backward-compatible alias for existing imports.
signalsBackend = SignalsBackend

