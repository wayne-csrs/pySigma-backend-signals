from sigma.pipelines.common import (
    logsource_linux_file_create,
    logsource_linux_network_connection,
    logsource_linux_process_creation,
    logsource_macos_file_create,
    logsource_macos_process_creation,
    logsource_windows_file_access,
    logsource_windows_file_change,
    logsource_windows_file_delete,
    logsource_windows_file_event,
    logsource_windows_file_rename,
    logsource_windows_image_load,
    logsource_windows_network_connection,
    logsource_windows_process_creation,
    logsource_windows_registry_event,
    logsource_windows_registry_set,
)
from sigma.processing.conditions import LogsourceCondition

# Shared file field map: path mapping is independent of file.operation.
FILE_FIELD_MAPPINGS = {
    "Image": "process.path",
    "TargetFilename": "file.path",
    "FileName": "file.name",
    "sha256": "file.hash_sha256",
    "sha1": "file.hash_sha1",
    "md5": "file.hash_md5",
}

PROCESS_CREATION_FIELD_MAPPINGS = {
    "Image": "process.path",
    "ProcessName": "process.name",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent_path",
    "ParentProcessName": "process.parent_name",
    "ParentCommandLine": "process.parent_command_line",
    "GrandparentImage": "process.ancestry_path",
    "GrandParentImage": "process.ancestry_path",
    "CurrentDirectory": "process.working_directory",
    "IntegrityLevel": "process.integrity_level",
    "sha256": "process.hash_sha256",
    "sha1": "process.hash_sha1",
    "md5": "process.hash_md5",
}

NETWORK_CONNECTION_FIELD_MAPPINGS = {
    "Image": "process.path",
    "ProcessName": "process.name",
    "CommandLine": "process.command_line",
    "Protocol": "network.protocol",
    "SourceIp": "network.source_ip",
    "SourcePort": "network.source_port",
    "DestinationIp": "network.destination_ip",
    "DestinationPort": "network.port",
    "DestinationHostname": "network.destination_domain",
    "Signed": "process.signature_status",
    "SignatureStatus": "process.signature_status",
}

# Rule categories -> rule conditions
CATEGORY_TO_CONDITIONS_FACTORIES = {
    "windows_process_creation": logsource_windows_process_creation,
    "windows_image_load": logsource_windows_image_load,
    "windows_file_event": logsource_windows_file_event,
    "windows_file_create": lambda: LogsourceCondition(
        product="windows", category="file_create"
    ),
    "windows_file_delete": logsource_windows_file_delete,
    "windows_file_change": logsource_windows_file_change,
    "windows_file_rename": logsource_windows_file_rename,
    "windows_file_access": logsource_windows_file_access,
    "windows_network_connection": logsource_windows_network_connection,
    "windows_registry_event": logsource_windows_registry_event,
    "windows_registry_set": logsource_windows_registry_set,
    "linux_process_creation": logsource_linux_process_creation,
    "linux_network_connection": logsource_linux_network_connection,
    "linux_file_create": logsource_linux_file_create,
    "linux_file_event": lambda: LogsourceCondition(
        product="linux", category="file_event"
    ),
    "macos_process_creation": logsource_macos_process_creation,
    "macos_file_create": logsource_macos_file_create,
    "macos_file_event": lambda: LogsourceCondition(
        product="macos", category="file_event"
    ),
}

# Generic mappings that apply to all rule categories.
GENERIC_FIELD_MAPPINGS = {
    "User": "user.name",
    "UserName": "user.name",
    "LogonId": "user.logon_id",
}

# Rule category -> field mappings
CATEGORY_FIELD_MAPPINGS = {
    "windows_process_creation": {
        **PROCESS_CREATION_FIELD_MAPPINGS,
    },
    "windows_image_load": {
        "Image": "process.path",
        "ImageLoaded": "module.path",
        "ProcessName": "process.name",
        "CommandLine": "process.command_line",
        "sha256": "module.hash_sha256",
        "sha1": "module.hash_sha1",
        "md5": "module.hash_md5",
    },
    "windows_file_event": FILE_FIELD_MAPPINGS,
    "windows_file_create": FILE_FIELD_MAPPINGS,
    "windows_file_delete": FILE_FIELD_MAPPINGS,
    "windows_file_change": FILE_FIELD_MAPPINGS,
    "windows_file_rename": FILE_FIELD_MAPPINGS,
    "windows_file_access": FILE_FIELD_MAPPINGS,
    "windows_network_connection": NETWORK_CONNECTION_FIELD_MAPPINGS,
    "windows_registry_event": {
        "Image": "process.path",
        "TargetObject": "registry.key_path",
        "RegistryKey": "registry.key_path",
        "RegistryValueName": "registry.value_name",
        "RegistryValueData": "registry.value_data",
        "Details": "registry.value_data",
    },
    "windows_registry_set": {
        "Image": "process.path",
        "TargetObject": "registry.key_path",
        "RegistryKey": "registry.key_path",
        "RegistryValueName": "registry.value_name",
        "RegistryValueData": "registry.value_data",
        "Details": "registry.value_data",
    },
    "linux_process_creation": {
        k: v
        for k, v in PROCESS_CREATION_FIELD_MAPPINGS.items()
        if k != "IntegrityLevel"
    },
    "linux_network_connection": NETWORK_CONNECTION_FIELD_MAPPINGS,
    "linux_file_create": FILE_FIELD_MAPPINGS,
    "linux_file_event": FILE_FIELD_MAPPINGS,
    "macos_process_creation": {
        k: v
        for k, v in PROCESS_CREATION_FIELD_MAPPINGS.items()
        if k != "IntegrityLevel"
    },
    "macos_file_create": FILE_FIELD_MAPPINGS,
    "macos_file_event": FILE_FIELD_MAPPINGS,
}

# Sigma signature values -> Tanium Signals signature_status values.
SIGNATURE_STATUS_VALUE_MAP = {
    "false": "no_signature",
    "unsigned": "no_signature",
    "unavailable": "no_signature",
    "invalid": "unverified",
    "expired": "unverified",
    "untrusted": "unverified",
    "error": "unverified",
    "unverified": "unverified",
    "true": "verified",
    "valid": "verified",
    "trusted": "verified",
    "verified": "verified",
}

GRANDPARENT_MANUAL_REVIEW_MESSAGE = (
    "Tanium cannot identify the exact grandparent process. "
    "Manual analyst review is required."
)
