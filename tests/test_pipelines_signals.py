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
            category: driver_load
        detection:
            sel:
                ImageLoaded: C:\\Windows\\System32\\drivers\\evil.sys
            condition: sel
        """
    )

    with pytest.raises(SigmaTransformationError, match="Unsupported Signals logsource"):
        SignalsBackend().convert(rule)


def test_signals_create_remote_thread_returns_manual_review_message() -> None:
    """create_remote_thread cannot be expressed in Tanium Signals (TDE2148)."""
    query = SignalsBackend().convert(
        SigmaCollection.from_yaml(
            """
            title: Remote Thread Unsupported Test
            status: test
            logsource:
                product: windows
                category: create_remote_thread
            detection:
                mstsc_process:
                    TargetImage|endswith: '\\mstsc.exe'
                condition: mstsc_process
            """
        )
    )[0]

    assert query == (
        "Unsupported telemetry: Tanium Signals cannot represent create_remote_thread. "
        "Manual review is required."
    )
    assert "TargetImage" not in query
    assert "mstsc" not in query


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


def test_signals_pipeline_image_load_path_and_signature_status() -> None:
    """ImageLoaded -> image.path; Signed/SignatureStatus -> image.signature_status.

    Pattern from global-rule-library [TDE2371]-lsass_loading_suspicious_dll.
    """
    query = SignalsBackend().convert(
        SigmaCollection.from_yaml(
            """
            title: Image Load Signature Mapping Test
            status: test
            logsource:
                product: windows
                category: image_load
            detection:
                lsass_process:
                    Image|endswith: '\\lsass.exe'
                dll_file:
                    ImageLoaded|endswith: '.dll'
                invalid_signature:
                    SignatureStatus: 'invalid'
                unsigned_module:
                    Signed: 'false'
                condition: lsass_process and dll_file
                    and (invalid_signature or unsigned_module)
            """
        )
    )[0]

    assert "image.path ends with '.dll'" in query
    assert "image.signature_status is 'unverified'" in query
    assert "image.signature_status is 'no_signature'" in query
    assert "module.path" not in query
    assert "SignatureStatus" not in query
    assert "Signed" not in query


def test_signals_pipeline_network_port_signature_and_operation() -> None:
    """DestinationPort, Signature null, and default connect (TDE2268)."""
    query = SignalsBackend().convert(
        SigmaCollection.from_yaml(
            """
            title: Network Mapping Test
            status: test
            logsource:
                product: windows
                category: network_connection
            detection:
                user_writable_path:
                    Image|contains: '\\AppData\\'
                sign_vendor_null:
                    Signature: null
                php_in_cmd:
                    CommandLine|contains: '.php'
                web_ports:
                    DestinationPort:
                        - 80
                        - 443
                condition: user_writable_path and sign_vendor_null and php_in_cmd and web_ports
            """
        )
    )[0]

    assert "network.port is 80" in query
    assert "network.port is 443" in query
    assert "network.destination_port" not in query
    assert "process.signature_status is 'no_signature'" in query
    assert "Signature is null" not in query
    assert "network.operation is 'connect'" in query


def test_signals_pipeline_network_operation_accept() -> None:
    query = SignalsBackend().convert(
        SigmaCollection.from_yaml(
            """
            title: Network Accept Test
            status: test
            logsource:
                product: windows
                category: network_connection
            detection:
                sel:
                    DestinationPort: 445
                    Initiated: 'false'
                condition: sel
            """
        )
    )[0]

    assert "network.port is 445" in query
    assert "network.operation is 'accept'" in query
    assert "network.operation is 'connect'" not in query


def test_signals_pipeline_linux_file_event_target_filename() -> None:
    """Linux file_event maps TargetFilename without file.operation (TDE2173)."""
    query = SignalsBackend().convert(
        SigmaCollection.from_yaml(
            """
            title: PAM Tampering Mapping Test
            status: test
            logsource:
                product: linux
                category: file_event
            detection:
                pam_unix_so:
                    TargetFilename:
                        - /lib/security/pam_unix.so
                        - /usr/lib/security/pam_unix.so
                condition: pam_unix_so
            """
        )
    )[0]

    assert "file.path is '/lib/security/pam_unix.so'" in query
    assert "file.operation" not in query


def test_signals_pipeline_windows_file_delete_target_filename() -> None:
    query = SignalsBackend().convert(
        SigmaCollection.from_yaml(
            """
            title: File Delete Mapping Test
            status: test
            logsource:
                product: windows
                category: file_delete
            detection:
                sel:
                    TargetFilename|endswith: '\\evil.dll'
                condition: sel
            """
        )
    )[0]

    assert "file.path ends with" in query
    assert "evil.dll" in query
    assert "file.operation" not in query


def test_signals_pipeline_grandparent_ancestry_manual_review() -> None:
    """GrandparentImage -> process.ancestry_path with review note (TDE2306)."""
    query = SignalsBackend().convert(
        SigmaCollection.from_yaml(
            """
            title: Ancestry Mapping Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    Image|endswith: '\\reg.exe'
                    GrandparentImage|endswith: '\\node.exe'
                condition: sel
            """
        )
    )[0]

    assert "process.ancestry_path ends with" in query
    assert "node.exe" in query
    assert "GrandparentImage" not in query
    assert "MANUAL REVIEW: Tanium cannot identify the exact grandparent process." in query
