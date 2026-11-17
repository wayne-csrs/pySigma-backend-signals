from dataclasses import dataclass
from typing import Iterable, Optional, Union

from sigma.pipelines.base import Pipeline
from sigma.processing.conditions import (
    IncludeFieldCondition,
    LogsourceCondition,
    RuleContainsFieldCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
    SetStateTransformation,
)
from sigma.processing.transformations.detection_item import DetectionItemTransformation
from sigma.processing.transformations.values import ValueTransformation
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaBool, SigmaNull, SigmaString, SigmaType
from sigma.pipelines.signals.mappings import (
    CATEGORY_FIELD_MAPPINGS,
    CATEGORY_TO_CONDITIONS_FACTORIES,
    GENERIC_FIELD_MAPPINGS,
    GRANDPARENT_MANUAL_REVIEW_MESSAGE,
    SIGNATURE_STATUS_VALUE_MAP,
)


@dataclass
class SignatureStatusValueTransformation(ValueTransformation):
    """Map Sigma Signed/SignatureStatus values to Tanium signature_status values."""

    def apply_value(
        self, field: Optional[str], val: SigmaType
    ) -> Union[SigmaType, list[SigmaType], None]:
        if isinstance(val, SigmaBool):
            key = "true" if val.boolean else "false"
        elif isinstance(val, SigmaString):
            key = str(val).lower()
        else:
            return None

        mapped = SIGNATURE_STATUS_VALUE_MAP.get(key)
        if mapped is None:
            return None
        return SigmaString(mapped)


@dataclass
class SignatureNullToStatusTransformation(DetectionItemTransformation):
    """Rewrite Signature/ProcessSignature null into process.signature_status no_signature."""

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[SigmaDetectionItem]:
        if detection_item.field not in ("Signature", "ProcessSignature"):
            return None
        if len(detection_item.value) != 1 or not isinstance(
            detection_item.value[0], SigmaNull
        ):
            return None
        return SigmaDetectionItem(
            "process.signature_status",
            [],
            [SigmaString("no_signature")],
        )


@dataclass
class InitiatedToNetworkOperationTransformation(DetectionItemTransformation):
    """Rewrite Initiated true/false into network.operation connect/accept."""

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[SigmaDetectionItem]:
        if detection_item.field != "Initiated":
            return None
        if len(detection_item.value) != 1:
            return None

        value = detection_item.value[0]
        if isinstance(value, SigmaBool):
            initiated = value.boolean
        elif isinstance(value, SigmaString):
            initiated = str(value).lower() == "true"
        else:
            return None

        operation = "connect" if initiated else "accept"
        return SigmaDetectionItem(
            "network.operation",
            [],
            [SigmaString(operation)],
        )


def _network_category_or_destination_without_initiated(
    results: Iterable[bool],
) -> bool:
    """network_connection AND DestinationPort AND NOT Initiated."""
    values = list(results)
    return bool(values[0] and values[1] and not values[2])


@Pipeline
def signals_pipeline() -> ProcessingPipeline:
    items = [
        ProcessingItem(
            identifier="signals_unsupported_logsource",
            transformation=RuleFailureTransformation(
                message=(
                    "Unsupported Signals logsource. Supported product/category "
                    f"combinations: {', '.join(sorted(CATEGORY_FIELD_MAPPINGS))}"
                )
            ),
            rule_conditions=[
                condition_factory()
                for condition_factory in CATEGORY_TO_CONDITIONS_FACTORIES.values()
            ],
            rule_condition_linking=any,
            rule_condition_negation=True,
        ),
        ProcessingItem(
            identifier="signals_base_field_mapping",
            transformation=FieldMappingTransformation(GENERIC_FIELD_MAPPINGS),
        ),
        # Add default connect before Initiated is rewritten, so absence of Initiated
        # can still be detected from the original field name.
        ProcessingItem(
            identifier="signals_default_network_operation_connect",
            transformation=AddConditionTransformation(
                {"network.operation": "connect"}
            ),
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                RuleContainsFieldCondition("DestinationPort"),
                RuleContainsFieldCondition("Initiated"),
            ],
            rule_condition_linking=_network_category_or_destination_without_initiated,
        ),
        ProcessingItem(
            identifier="signals_initiated_to_network_operation",
            transformation=InitiatedToNetworkOperationTransformation(),
            rule_conditions=[LogsourceCondition(category="network_connection")],
            field_name_conditions=[IncludeFieldCondition(fields=["Initiated"])],
        ),
        ProcessingItem(
            identifier="signals_signature_null_to_no_signature",
            transformation=SignatureNullToStatusTransformation(),
            rule_conditions=[LogsourceCondition(category="network_connection")],
            field_name_conditions=[
                IncludeFieldCondition(fields=["Signature", "ProcessSignature"])
            ],
        ),
        ProcessingItem(
            identifier="signals_network_signature_status_values",
            transformation=SignatureStatusValueTransformation(),
            rule_conditions=[LogsourceCondition(category="network_connection")],
            field_name_conditions=[
                IncludeFieldCondition(fields=["Signed", "SignatureStatus"])
            ],
        ),
        ProcessingItem(
            identifier="signals_grandparent_manual_review",
            transformation=SetStateTransformation(
                key="manual_review",
                val=[GRANDPARENT_MANUAL_REVIEW_MESSAGE],
            ),
            rule_conditions=[
                RuleContainsFieldCondition("GrandparentImage"),
                RuleContainsFieldCondition("GrandParentImage"),
            ],
            rule_condition_linking=any,
        ),
    ]

    for category, field_mappings in CATEGORY_FIELD_MAPPINGS.items():
        items.append(
            ProcessingItem(
                identifier=f"signals_field_mapping_{category}",
                transformation=FieldMappingTransformation(field_mappings),
                rule_conditions=[CATEGORY_TO_CONDITIONS_FACTORIES[category]()],
            )
        )

    return ProcessingPipeline(
        name="Tanium Signals field mapping",
        allowed_backends=frozenset({"signals"}),
        priority=20,
        items=items,
    )
