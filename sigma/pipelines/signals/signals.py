from sigma.pipelines.base import Pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    RuleFailureTransformation,
)
from sigma.pipelines.signals.mappings import (
    CATEGORY_FIELD_MAPPINGS,
    CATEGORY_TO_CONDITIONS_MAPPINGS,
    GENERIC_FIELD_MAPPINGS,
    UNSUPPORTED_LOGSOURCES,
)

# Future pipeline imports you may enable later:
# from sigma.processing.conditions import (
#     IncludeFieldCondition,
#     ExcludeFieldCondition,
#     RuleProcessingItemAppliedCondition,
# )
# from sigma.processing.postprocessing import EmbedQueryTransformation
# from sigma.processing.pipeline import QueryPostprocessingItem
# from sigma.processing.transformations import (
#     AddConditionTransformation,
#     DetectionItemFailureTransformation,
#     RuleFailureTransformation,
#     SetStateTransformation,
# )


@Pipeline
def signals_pipeline() -> ProcessingPipeline:
    items = [
        ProcessingItem(
            identifier=f"signals_unsupported_{category}",
            transformation=RuleFailureTransformation(
                f"The '{category}' category is not supported by the Tanium Signals "
                f"backend {reason}"
            ),
            rule_conditions=[condition],
        )
        for category, condition, reason in UNSUPPORTED_LOGSOURCES
    ]
    items.append(
        ProcessingItem(
            identifier="signals_base_field_mapping",
            transformation=FieldMappingTransformation(GENERIC_FIELD_MAPPINGS),
        )
    )

    for category, field_mappings in CATEGORY_FIELD_MAPPINGS.items():
        items.append(
            ProcessingItem(
                identifier=f"signals_field_mapping_{category}",
                transformation=FieldMappingTransformation(field_mappings),
                rule_conditions=[CATEGORY_TO_CONDITIONS_MAPPINGS[category]],
            )
        )

    return ProcessingPipeline(
        name="Tanium Signals field mapping",
        allowed_backends=frozenset({"signals"}),
        priority=20,
        items=items,
    )