import pytest
from sigma.exceptions import SigmaTransformationError
from sigma.backends.signals import SignalsBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.signals import signals_pipeline


def test_signals_pipeline_can_be_instantiated_multiple_times() -> None:
    assert signals_pipeline() is not signals_pipeline()


def test_signals_pipeline_rejects_unsupported_category() -> None:
    rule = SigmaCollection.from_yaml(
        """
        title: Unsupported Category Test
        status: test
        logsource:
            product: windows
            category: create_remote_thread
        detection:
            sel:
                TargetImage: C:\\Windows\\System32\\mstsc.exe
            condition: sel
        """
    )

    with pytest.raises(SigmaTransformationError, match="Unsupported Signals logsource"):
        SignalsBackend().convert(rule)


def test_signals_pipeline_field_mapping_applied() -> None:
    backend = SignalsBackend()
    query = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Pipeline Mapping Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: C:\\Windows\\System32\\cmd.exe
                    CommandLine|contains: /c whoami
                condition: sel
            """
        )
    )[0]

    assert "process.path" in query
    assert "process.command_line" in query


def test_signals_pipeline_linux_process_creation_field_mapping_applied() -> None:
    backend = SignalsBackend()
    query = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Pipeline Mapping Linux Process Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: /usr/bin/bash
                    CommandLine|contains: whoami
                condition: sel
            """
        )
    )[0]

    assert "process.path" in query
    assert "process.command_line" in query


def test_signals_pipeline_macos_file_create_field_mapping_applied() -> None:
    backend = SignalsBackend()
    query = backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Pipeline Mapping macOS File Test
            status: test
            logsource:
                category: file_create
                product: macos
            detection:
                sel:
                    TargetFilename: /tmp/suspicious.bin
                condition: sel
            """
        )
    )[0]

    assert "file.path" in query