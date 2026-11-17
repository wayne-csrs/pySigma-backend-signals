from dataclasses import dataclass
from typing import Optional, Union

from sigma.pipelines.base import Pipeline
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    RuleFailureTransformation,
)
from sigma.processing.transformations.values import ValueTransformation
from sigma.types import SigmaBool, SigmaString, SigmaType
from sigma.pipelines.signals.mappings import (
    CATEGORY_FIELD_MAPPINGS,
    CATEGORY_TO_CONDITIONS_FACTORIES,
    GENERIC_FIELD_MAPPINGS,
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
        ProcessingItem(
            identifier="signals_image_load_signature_status_values",
            transformation=SignatureStatusValueTransformation(),
            rule_conditions=[CATEGORY_TO_CONDITIONS_FACTORIES["windows_image_load"]()],
            field_name_conditions=[
                IncludeFieldCondition(fields=["Signed", "SignatureStatus"])
            ],
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
