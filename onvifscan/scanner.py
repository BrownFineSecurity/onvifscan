"""
Core onvifscan functionality - ONVIF device scanning and testing.
"""

import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from .interfaces import ToolConfig, ToolResult


# Common SOAP envelope template
SOAP_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        {body}
    </s:Body>
</s:Envelope>"""

# ONVIF request templates (comprehensive set from Device, Media, Event, PTZ, Recording services)
REQUESTS = [
    # Device Management Service (http://www.onvif.org/ver10/device/wsdl)
    {
        "name": "GetServices",
        "endpoint": "/onvif/device_service",
        "body": '<GetServices xmlns="http://www.onvif.org/ver10/device/wsdl"><IncludeCapability>true</IncludeCapability></GetServices>',
        "auth_required": False,
        "description": "Retrieves list of supported services and their capabilities. Unauthenticated by design."
    },
    {
        "name": "GetSystemDateAndTime",
        "endpoint": "/onvif/device_service",
        "body": '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": False,
        "description": "Gets device date and time. Unauthenticated by design."
    },
    {
        "name": "GetCapabilities",
        "endpoint": "/onvif/device_service",
        "body": '<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl"><Category>All</Category></GetCapabilities>',
        "auth_required": False,
        "description": "Gets device capabilities (older version of GetServices). Unauthenticated by design."
    },
    {
        "name": "GetDeviceInformation",
        "endpoint": "/onvif/device_service",
        "body": '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets device info (manufacturer, model, firmware). Sensitive if unauthenticated."
    },
    {
        "name": "GetHostname",
        "endpoint": "/onvif/device_service",
        "body": '<GetHostname xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets device hostname. Sensitive network info."
    },
    {
        "name": "GetNetworkInterfaces",
        "endpoint": "/onvif/device_service",
        "body": '<GetNetworkInterfaces xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets network interface details. Highly sensitive if unauthenticated."
    },
    {
        "name": "GetDNS",
        "endpoint": "/onvif/device_service",
        "body": '<GetDNS xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets DNS settings. Sensitive network config."
    },
    {
        "name": "GetNTP",
        "endpoint": "/onvif/device_service",
        "body": '<GetNTP xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets NTP server settings. Sensitive network info."
    },
    {
        "name": "GetUsers",
        "endpoint": "/onvif/device_service",
        "body": '<GetUsers xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets user account list. Critical if unauthenticated."
    },
    {
        "name": "GetNetworkProtocols",
        "endpoint": "/onvif/device_service",
        "body": '<GetNetworkProtocols xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets network protocol settings (e.g., HTTP, RTSP). Sensitive."
    },

    # Media Service (http://www.onvif.org/ver10/media/wsdl)
    {
        "name": "GetProfiles",
        "endpoint": None,  # Updated after GetServices
        "body": '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets media profiles (stream configs). Sensitive if unauthenticated."
    },
    {
        "name": "GetVideoSources",
        "endpoint": None,
        "body": '<GetVideoSources xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets video source details. Sensitive stream info."
    },
    {
        "name": "GetAudioSources",
        "endpoint": None,
        "body": '<GetAudioSources xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets audio source information. Sensitive audio surveillance."
    },
    {
        "name": "GetSnapshotUri",
        "endpoint": None,
        "body": '<GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl"><ProfileToken>Profile_1</ProfileToken></GetSnapshotUri>',
        "auth_required": True,
        "description": "Gets snapshot URI. Critical if unauthenticated (image access)."
    },
    {
        "name": "GetStreamUri",
        "endpoint": None,
        "body": '<GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl"><StreamSetup><Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream><Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport></StreamSetup><ProfileToken>Profile_1</ProfileToken></GetStreamUri>',
        "auth_required": True,
        "description": "Gets RTSP stream URI. Critical if unauthenticated (video access)."
    },

    # Event Service (http://www.onvif.org/ver10/events/wsdl)
    {
        "name": "GetEventProperties",
        "endpoint": None,
        "body": '<GetEventProperties xmlns="http://www.onvif.org/ver10/events/wsdl"/>',
        "auth_required": False,
        "description": "Gets event properties (e.g., supported events). Unauthenticated by design."
    },

    # PTZ Service (http://www.onvif.org/ver20/ptz/wsdl)
    {
        "name": "GetNodes",
        "endpoint": None,
        "body": '<GetNodes xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
        "auth_required": True,
        "description": "Gets PTZ nodes. Sensitive if unauthenticated (camera control)."
    },
    {
        "name": "GetPresets",
        "endpoint": None,
        "body": '<GetPresets xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile_1</ProfileToken></GetPresets>',
        "auth_required": True,
        "description": "Gets PTZ presets. Sensitive if unauthenticated."
    },

    # Imaging Service (http://www.onvif.org/ver20/imaging/wsdl)
    {
        "name": "GetImagingSettings",
        "endpoint": None,
        "body": '<GetImagingSettings xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken></GetImagingSettings>',
        "auth_required": True,
        "description": "Gets camera imaging settings (brightness, contrast, etc.). Sensitive camera config."
    },

    # Recording Service (http://www.onvif.org/ver10/recording/wsdl)
    {
        "name": "GetRecordings",
        "endpoint": None,
        "body": '<GetRecordings xmlns="http://www.onvif.org/ver10/recording/wsdl"/>',
        "auth_required": True,
        "description": "Gets list of recordings. Critical if unauthenticated (video access)."
    },

    # Device IO Service (http://www.onvif.org/ver10/deviceIO/wsdl)
    {
        "name": "GetDigitalInputs",
        "endpoint": "/onvif/deviceio",
        "body": '<GetDigitalInputs xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"/>',
        "auth_required": True,
        "description": "Gets digital input status/configuration. Sensitive I/O info."
    },
    {
        "name": "GetRelayOutputs",
        "endpoint": "/onvif/deviceio",
        "body": '<GetRelayOutputs xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"/>',
        "auth_required": True,
        "description": "Gets relay output status/configuration. Critical for physical access control."
    },

    # Search Service (http://www.onvif.org/ver10/search/wsdl)
    {
        "name": "GetSearchCapabilities",
        "endpoint": "/onvif/search",
        "body": '<GetServiceCapabilities xmlns="http://www.onvif.org/ver10/search/wsdl"/>',
        "auth_required": False,
        "description": "Gets search service capabilities. Unauthenticated by design."
    },

    # Additional Device Management operations
    {
        "name": "GetDynamicDNS",
        "endpoint": "/onvif/device_service",
        "body": '<GetDynamicDNS xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets dynamic DNS settings. Sensitive network configuration."
    },
    {
        "name": "GetZeroConfiguration",
        "endpoint": "/onvif/device_service",
        "body": '<GetZeroConfiguration xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets zeroconf/UPnP settings. Could leak network topology."
    },
    {
        "name": "GetScopes",
        "endpoint": "/onvif/device_service",
        "body": '<GetScopes xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": False,
        "description": "Gets device scopes (location, hardware info). Unauthenticated by design."
    },
    {
        "name": "GetCertificatesStatus",
        "endpoint": "/onvif/device_service",
        "body": '<GetCertificatesStatus xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets certificate status. Privacy risk if unauthenticated."
    },
    {
        "name": "GetDiscoveryMode",
        "endpoint": "/onvif/device_service",
        "body": '<GetDiscoveryMode xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets discovery mode settings. Reveals network discoverability."
    },

    # Additional Media Service operations
    {
        "name": "GetVideoEncoderConfigurations",
        "endpoint": None,
        "body": '<GetVideoEncoderConfigurations xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets video encoder configurations. Sensitive stream details."
    },
    {
        "name": "GetMetadataConfigurations",
        "endpoint": None,
        "body": '<GetMetadataConfigurations xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets metadata configurations. Could leak analytics data."
    },
    {
        "name": "GetCompatibleVideoSources",
        "endpoint": None,
        "body": '<GetCompatibleVideoSources xmlns="http://www.onvif.org/ver10/media/wsdl"><ProfileToken>Profile_1</ProfileToken></GetCompatibleVideoSources>',
        "auth_required": True,
        "description": "Gets compatible video sources for a profile. Sensitive video info."
    },
    {
        "name": "GetServiceCapabilities",
        "endpoint": None,
        "body": '<GetServiceCapabilities xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": False,
        "description": "Gets media service capabilities. Unauthenticated by design."
    },

    # Additional Events Service operations
    {
        "name": "CreatePullPointSubscription",
        "endpoint": None,
        "body": '<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"><InitialTerminationTime>PT60S</InitialTerminationTime></CreatePullPointSubscription>',
        "auth_required": True,
        "description": "Creates event subscription. DoS/info leak risk if unauthenticated."
    },
    {
        "name": "GetEventBrokers",
        "endpoint": None,
        "body": '<GetEventBrokers xmlns="http://www.onvif.org/ver10/events/wsdl"/>',
        "auth_required": True,
        "description": "Gets event brokers. Sensitive event infrastructure info."
    },

    # Additional PTZ Service operations
    {
        "name": "GetConfigurations",
        "endpoint": None,
        "body": '<GetConfigurations xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
        "auth_required": True,
        "description": "Gets PTZ configurations. Sensitive camera movement limits."
    },
    {
        "name": "GetStatus",
        "endpoint": None,
        "body": '<GetStatus xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile_1</ProfileToken></GetStatus>',
        "auth_required": True,
        "description": "Gets current PTZ status. Privacy violation if unauthenticated."
    },

    # Additional Imaging Service operations
    {
        "name": "GetOptions",
        "endpoint": None,
        "body": '<GetOptions xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken></GetOptions>',
        "auth_required": True,
        "description": "Gets imaging options. Sensitive camera capabilities."
    },

    # Additional Recording Service operations
    {
        "name": "GetRecordingConfiguration",
        "endpoint": None,
        "body": '<GetRecordingConfiguration xmlns="http://www.onvif.org/ver10/recording/wsdl"><RecordingToken>Recording_1</RecordingToken></GetRecordingConfiguration>',
        "auth_required": True,
        "description": "Gets recording configuration. Critical recording details."
    },
    {
        "name": "ExportRecordedData",
        "endpoint": None,
        "body": '<ExportRecordedData xmlns="http://www.onvif.org/ver10/recording/wsdl"><SearchScope><IncludedSources><Token>Recording_1</Token></IncludedSources></SearchScope><FileFormat>MP4</FileFormat></ExportRecordedData>',
        "auth_required": True,
        "description": "Exports recorded data. Huge privacy risk if unauthenticated."
    },

    # Additional Replay Service operations
    {
        "name": "GetReplayUri",
        "endpoint": "/onvif/replay",
        "body": '<GetReplayUri xmlns="http://www.onvif.org/ver10/replay/wsdl"><StreamSetup><Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream><Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport></StreamSetup><RecordingToken>Recording_1</RecordingToken></GetReplayUri>',
        "auth_required": True,
        "description": "Gets replay URI. Critical for accessing recordings."
    },

    # Analytics Service operations
    {
        "name": "GetSupportedAnalyticsModules",
        "endpoint": None,
        "body": '<GetSupportedAnalyticsModules xmlns="http://www.onvif.org/ver20/analytics/wsdl"><ConfigurationToken>Analytics_1</ConfigurationToken></GetSupportedAnalyticsModules>',
        "auth_required": True,
        "description": "Gets supported analytics modules. Sensitive video analytics."
    },
    {
        "name": "GetAnalyticsDeviceInformation",
        "endpoint": None,
        "body": '<GetAnalyticsDeviceInformation xmlns="http://www.onvif.org/ver20/analytics/wsdl"/>',
        "auth_required": True,
        "description": "Gets analytics device information. Reveals analytics engine details."
    },

    # Additional Device IO Service operations
    {
        "name": "GetSerialPorts",
        "endpoint": "/onvif/deviceio",
        "body": '<GetSerialPorts xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"/>',
        "auth_required": True,
        "description": "Gets serial port configurations. Hardware interface details."
    },
    {
        "name": "SetRelayOutputState",
        "endpoint": "/onvif/deviceio",
        "body": '<SetRelayOutputState xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"><RelayOutputToken>Relay_1</RelayOutputToken><LogicalState>false</LogicalState></SetRelayOutputState>',
        "auth_required": True,
        "description": "Sets relay output state. Critical for physical control if unauthenticated."
    },

    # Additional Search Service operations
    {
        "name": "FindEvents",
        "endpoint": "/onvif/search",
        "body": '<FindEvents xmlns="http://www.onvif.org/ver10/search/wsdl"><StartPoint>2023-01-01T00:00:00Z</StartPoint><EndPoint>2023-01-02T00:00:00Z</EndPoint></FindEvents>',
        "auth_required": True,
        "description": "Searches for events. Could leak historical event data."
    },

    # Receiver Service operations
    {
        "name": "GetReceivers",
        "endpoint": "/onvif/receiver",
        "body": '<GetReceivers xmlns="http://www.onvif.org/ver10/receiver/wsdl"/>',
        "auth_required": True,
        "description": "Gets receiver configurations. Sensitive stream receiver details."
    },

    # Provisioning Service operations
    {
        "name": "GetProvisioning",
        "endpoint": "/onvif/provisioning",
        "body": '<GetProvisioning xmlns="http://www.onvif.org/ver10/provisioning/wsdl"/>',
        "auth_required": True,
        "description": "Gets provisioning information. Device setup details."
    },

    # Advanced Security Service operations
    {
        "name": "GetSupportedKeystores",
        "endpoint": "/onvif/advancedsecurity",
        "body": '<GetSupportedKeystores xmlns="http://www.onvif.org/ver10/advancedsecurity/wsdl"/>',
        "auth_required": True,
        "description": "Gets supported keystores. Certificate management info."
    },

    # DESTRUCTIVE/NICHE OPERATIONS - Only run with -a/--all flag
    # PTZ Service - Destructive
    {
        "name": "ContinuousMove",
        "endpoint": None,
        "body": '<ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile1</ProfileToken><Velocity><PanTilt xmlns="http://www.onvif.org/ver10/schema" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace" x="0.0" y="0.0"/><Zoom xmlns="http://www.onvif.org/ver10/schema" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace" x="0.0"/></Velocity></ContinuousMove>',
        "auth_required": True,
        "description": "Attempts continuous PTZ movement (destructive - may move camera).",
        "destructive": True
    },
    {
        "name": "AbsoluteMove",
        "endpoint": None,
        "body": '<AbsoluteMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile1</ProfileToken><Position><PanTilt xmlns="http://www.onvif.org/ver10/schema" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace" x="0.0" y="0.0"/><Zoom xmlns="http://www.onvif.org/ver10/schema" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace" x="0.0"/></Position></AbsoluteMove>',
        "auth_required": True,
        "description": "Attempts absolute PTZ movement (destructive - may move camera).",
        "destructive": True
    },

    # Imaging Service - Destructive
    {
        "name": "Move",
        "endpoint": None,
        "body": '<Move xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken><Focus><Absolute>50</Absolute></Focus></Move>',
        "auth_required": True,
        "description": "Attempts to move camera focus (destructive - may adjust lens).",
        "destructive": True
    },
    {
        "name": "Stop",
        "endpoint": None,
        "body": '<Stop xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken></Stop>',
        "auth_required": True,
        "description": "Attempts to stop imaging movement (destructive).",
        "destructive": True
    },

    # Recording Service - Destructive
    {
        "name": "CreateRecording",
        "endpoint": None,
        "body": '<CreateRecording xmlns="http://www.onvif.org/ver10/recording/wsdl"><RecordingConfiguration><Source><SourceToken>VideoSource_1</SourceToken><Name>TestRecording</Name></Source><Content>Video</Content></RecordingConfiguration></CreateRecording>',
        "auth_required": True,
        "description": "Attempts to create a recording (destructive - may create storage).",
        "destructive": True
    },
    {
        "name": "DeleteRecording",
        "endpoint": None,
        "body": '<DeleteRecording xmlns="http://www.onvif.org/ver10/recording/wsdl"><RecordingToken>Recording_1</RecordingToken></DeleteRecording>',
        "auth_required": True,
        "description": "Attempts to delete a recording (destructive - may delete data).",
        "destructive": True
    },

    # Analytics Service - Destructive
    {
        "name": "CreateAnalyticsModules",
        "endpoint": None,
        "body": '<CreateAnalyticsModules xmlns="http://www.onvif.org/ver20/analytics/wsdl"><ConfigurationToken>Analytics_1</ConfigurationToken><AnalyticsModule><Name>TestModule</Name><Type>tt:CellMotionDetector</Type></AnalyticsModule></CreateAnalyticsModules>',
        "auth_required": True,
        "description": "Attempts to create analytics modules (destructive - may add processing rules).",
        "destructive": True
    },

    # Device Management Service - Highly Destructive
    {
        "name": "SetSystemFactoryDefault",
        "endpoint": "/onvif/device_service",
        "body": '<SetSystemFactoryDefault xmlns="http://www.onvif.org/ver10/device/wsdl"><FactoryDefault>Hard</FactoryDefault></SetSystemFactoryDefault>',
        "auth_required": True,
        "description": "Attempts to reset system to factory defaults (highly destructive).",
        "destructive": True
    },
    {
        "name": "UpgradeSystemFirmware",
        "endpoint": "/onvif/device_service",
        "body": '<UpgradeSystemFirmware xmlns="http://www.onvif.org/ver10/device/wsdl"><Firmware><Data>test</Data></Firmware></UpgradeSystemFirmware>',
        "auth_required": True,
        "description": "Attempts firmware upgrade (highly destructive).",
        "destructive": True
    },

    # Receiver Service - Destructive
    {
        "name": "CreateReceiver",
        "endpoint": "/onvif/receiver",
        "body": '<CreateReceiver xmlns="http://www.onvif.org/ver10/receiver/wsdl"><Configuration><Mode>AutoConnect</Mode><MediaUri>http://example.com/stream</MediaUri></Configuration></CreateReceiver>',
        "auth_required": True,
        "description": "Attempts to create a receiver (destructive - may add stream receiver).",
        "destructive": True
    },

    # Events Service - Potentially Destructive (if subscriptions exist)
    {
        "name": "Renew",
        "endpoint": None,
        "body": '<Renew xmlns="http://www.onvif.org/ver10/events/wsdl"><TerminationTime>PT60S</TerminationTime></Renew>',
        "auth_required": True,
        "description": "Attempts to renew event subscription (potentially destructive).",
        "destructive": True
    },
    {
        "name": "Unsubscribe",
        "endpoint": None,
        "body": '<Unsubscribe xmlns="http://www.onvif.org/ver10/events/wsdl"/>',
        "auth_required": True,
        "description": "Attempts to unsubscribe from events (potentially destructive).",
        "destructive": True
    },

    # Niche Services - Uncovered but potentially testable
    # Access Control Service
    {
        "name": "GetAccessPointInfo",
        "endpoint": "/onvif/accesscontrol",
        "body": '<GetAccessPointInfo xmlns="http://www.onvif.org/ver10/accesscontrol/wsdl"><Token>AccessPoint_1</Token></GetAccessPointInfo>',
        "auth_required": True,
        "description": "Gets access point information (physical security info).",
        "destructive": False
    },

    # Door Control Service
    {
        "name": "GetDoorState",
        "endpoint": "/onvif/doorcontrol",
        "body": '<GetDoorState xmlns="http://www.onvif.org/ver10/doorcontrol/wsdl"><Token>Door_1</Token></GetDoorState>',
        "auth_required": True,
        "description": "Gets door state (physical access status).",
        "destructive": False
    },

    # Credential Service
    {
        "name": "GetCredentials",
        "endpoint": "/onvif/credential",
        "body": '<GetCredentials xmlns="http://www.onvif.org/ver10/credential/wsdl"/>',
        "auth_required": True,
        "description": "Gets credential information (critical security data).",
        "destructive": False
    }
]

# Headers for SOAP requests
HEADERS = {
    "Content-Type": "application/soap+xml; charset=utf-8"
}


def parse_soap_fault(response_text: str) -> Dict[str, Any]:
    """
    Parse SOAP fault response to determine fault type.

    Returns dict with:
    - is_fault: bool - whether this is a SOAP fault
    - fault_type: str - 'auth', 'param_validation', 'not_implemented', 'other'
    - fault_code: str - the fault code value
    - fault_reason: str - the fault reason text
    """
    result = {
        'is_fault': False,
        'fault_type': 'other',
        'fault_code': '',
        'fault_reason': ''
    }

    try:
        root = ET.fromstring(response_text)

        # Check for SOAP Fault element
        fault = root.find(".//{http://www.w3.org/2003/05/soap-envelope}Fault")
        if fault is None:
            return result

        result['is_fault'] = True

        # Extract fault code
        value_elem = fault.find(".//{http://www.w3.org/2003/05/soap-envelope}Value")
        if value_elem is not None:
            result['fault_code'] = value_elem.text or ''

        # Extract subcode (more specific error)
        subcode_value = fault.findall(".//{http://www.w3.org/2003/05/soap-envelope}Subcode/{http://www.w3.org/2003/05/soap-envelope}Value")
        if subcode_value:
            result['fault_code'] = subcode_value[0].text or ''

        # Extract reason text
        reason_elem = fault.find(".//{http://www.w3.org/2003/05/soap-envelope}Text")
        if reason_elem is not None:
            result['fault_reason'] = reason_elem.text or ''

        # Classify fault type based on fault code and reason
        fault_code_lower = result['fault_code'].lower()
        fault_reason_lower = result['fault_reason'].lower()

        # Authentication/Authorization errors
        if any(x in fault_code_lower for x in ['notauthorized', 'unauthorized', 'notauthenticated']):
            result['fault_type'] = 'auth'
        elif any(x in fault_reason_lower for x in ['not authorized', 'unauthorized', 'authentication', 'not authenticated']):
            result['fault_type'] = 'auth'
        # Parameter validation errors (indicate the service is accessible but params are wrong)
        elif any(x in fault_code_lower for x in ['invalidargval', 'invalidargs', 'noconfig', 'noprofile', 'notoken']):
            result['fault_type'] = 'param_validation'
        elif any(x in fault_reason_lower for x in ['invalid argument', 'invalid parameter', 'no config', 'no profile']):
            result['fault_type'] = 'param_validation'
        # Not implemented errors
        elif 'not implemented' in fault_reason_lower or 'not recognized' in fault_reason_lower:
            result['fault_type'] = 'not_implemented'

    except ET.ParseError:
        pass

    return result


def send_request(request: Dict[str, Any], url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Send SOAP request and return response details."""
    soap_body = SOAP_ENVELOPE.format(body=request["body"])
    try:
        response = requests.post(url, headers=HEADERS, data=soap_body, timeout=timeout)

        # Parse SOAP fault if present
        fault_info = parse_soap_fault(response.text)

        return {
            "status_code": response.status_code,
            "content": response.text,
            "success": response.status_code == 200 and not fault_info['is_fault'],
            "fault_info": fault_info
        }
    except requests.RequestException as e:
        return {
            "status_code": None,
            "content": str(e),
            "success": False,
            "fault_info": {'is_fault': False, 'fault_type': 'other', 'fault_code': '', 'fault_reason': ''}
        }


def parse_get_services(response_text: str) -> Dict[str, str]:
    """Parse GetServices response to extract service endpoints."""
    endpoints = {}
    try:
        root = ET.fromstring(response_text)
        ns = {"ns": "http://www.onvif.org/ver10/device/wsdl"}
        services = root.findall(".//ns:Service", namespaces=ns)
        for service in services:
            namespace = service.find("ns:Namespace", namespaces=ns)
            xaddr = service.find("ns:XAddr", namespaces=ns)
            if namespace is not None and xaddr is not None:
                endpoints[namespace.text] = xaddr.text
    except ET.ParseError:
        pass
    return endpoints


def parse_profiles(response_text: str) -> List[str]:
    """Parse GetProfiles response to extract valid profile tokens."""
    profile_tokens = []
    try:
        root = ET.fromstring(response_text)
        # Look for Profile elements with token attribute
        # Namespaces can vary, so search broadly
        for profile in root.iter():
            if 'Profile' in profile.tag:
                token = profile.get('token')
                if token and token not in profile_tokens:
                    profile_tokens.append(token)
    except ET.ParseError:
        pass
    return profile_tokens


def parse_uris(response_text: str) -> List[str]:
    """Parse URIs from SOAP response XML."""
    uris = []
    try:
        root = ET.fromstring(response_text)
        for uri_elem in root.iter():
            if 'Uri' in uri_elem.tag and uri_elem.text:
                uris.append(uri_elem.text.strip())
    except ET.ParseError:
        pass
    return uris


def scan_onvif_device(base_url: str, test_all: bool = False, timeout: float = 5.0, verbose: bool = False, urls_only: bool = False) -> Dict[str, Any]:
    """Core ONVIF scanning logic."""
    base_url = base_url.rstrip('/')

    # First, get service endpoints
    get_services = next(req for req in REQUESTS if req["name"] == "GetServices")
    url = f"{base_url}{get_services['endpoint']}"
    response = send_request(get_services, url, timeout)

    if not response["success"]:
        return {
            'services_discovered': False,
            'error': 'Failed to retrieve services',
            'results': []
        }

    # Parse service endpoints
    endpoints = parse_get_services(response["content"])

    # Try to get valid profile tokens from GetProfiles
    profile_tokens = []
    media_endpoint = endpoints.get("http://www.onvif.org/ver10/media/wsdl")
    if media_endpoint:
        get_profiles_req = next((req for req in REQUESTS if req["name"] == "GetProfiles"), None)
        if get_profiles_req:
            profiles_response = send_request(get_profiles_req, media_endpoint, timeout)
            if profiles_response["success"]:
                profile_tokens = parse_profiles(profiles_response["content"])

    # Use first valid profile token, or fallback to common defaults
    valid_profile_token = profile_tokens[0] if profile_tokens else "Profile1"

    # Update request endpoints based on discovered services
    updated_requests = []
    for req in REQUESTS:
        req_copy = req.copy()

        # Skip destructive operations unless comprehensive mode (-a/--all)
        if req.get("destructive", False) and not test_all:
            continue

        # Update request body with valid profile token
        # Replace hardcoded profile tokens with discovered ones
        if "ProfileToken" in req_copy["body"]:
            # Replace Profile_1, Profile1, etc. with the valid token
            req_copy["body"] = req_copy["body"].replace("Profile_1", valid_profile_token)
            req_copy["body"] = req_copy["body"].replace("Profile1", valid_profile_token)

        if req["endpoint"] is None:
            # Look up service endpoint
            namespace = {
                # Media Service
                "GetProfiles": "http://www.onvif.org/ver10/media/wsdl",
                "GetVideoSources": "http://www.onvif.org/ver10/media/wsdl",
                "GetAudioSources": "http://www.onvif.org/ver10/media/wsdl",
                "GetSnapshotUri": "http://www.onvif.org/ver10/media/wsdl",
                "GetStreamUri": "http://www.onvif.org/ver10/media/wsdl",
                "GetVideoEncoderConfigurations": "http://www.onvif.org/ver10/media/wsdl",
                "GetMetadataConfigurations": "http://www.onvif.org/ver10/media/wsdl",
                "GetCompatibleVideoSources": "http://www.onvif.org/ver10/media/wsdl",
                "GetServiceCapabilities": "http://www.onvif.org/ver10/media/wsdl",
                # Events Service
                "GetEventProperties": "http://www.onvif.org/ver10/events/wsdl",
                "CreatePullPointSubscription": "http://www.onvif.org/ver10/events/wsdl",
                "GetEventBrokers": "http://www.onvif.org/ver10/events/wsdl",
                # PTZ Service
                "GetNodes": "http://www.onvif.org/ver20/ptz/wsdl",
                "GetPresets": "http://www.onvif.org/ver20/ptz/wsdl",
                "GetConfigurations": "http://www.onvif.org/ver20/ptz/wsdl",
                "GetStatus": "http://www.onvif.org/ver20/ptz/wsdl",
                # Imaging Service
                "GetImagingSettings": "http://www.onvif.org/ver20/imaging/wsdl",
                "GetOptions": "http://www.onvif.org/ver20/imaging/wsdl",
                # Recording Service
                "GetRecordings": "http://www.onvif.org/ver10/recording/wsdl",
                "GetRecordingConfiguration": "http://www.onvif.org/ver10/recording/wsdl",
                "ExportRecordedData": "http://www.onvif.org/ver10/recording/wsdl",
                # Analytics Service
                "GetSupportedAnalyticsModules": "http://www.onvif.org/ver20/analytics/wsdl",
                "GetAnalyticsDeviceInformation": "http://www.onvif.org/ver20/analytics/wsdl",
                # Destructive Operations
                "ContinuousMove": "http://www.onvif.org/ver20/ptz/wsdl",
                "AbsoluteMove": "http://www.onvif.org/ver20/ptz/wsdl",
                "Move": "http://www.onvif.org/ver20/imaging/wsdl",
                "Stop": "http://www.onvif.org/ver20/imaging/wsdl",
                "CreateRecording": "http://www.onvif.org/ver10/recording/wsdl",
                "DeleteRecording": "http://www.onvif.org/ver10/recording/wsdl",
                "CreateAnalyticsModules": "http://www.onvif.org/ver20/analytics/wsdl",
                "Renew": "http://www.onvif.org/ver10/events/wsdl",
                "Unsubscribe": "http://www.onvif.org/ver10/events/wsdl",
            }.get(req["name"])

            if namespace and namespace in endpoints:
                req_copy["endpoint"] = endpoints[namespace]
                updated_requests.append(req_copy)
            else:
                req_copy["endpoint"] = False
                updated_requests.append(req_copy)
        elif isinstance(req["endpoint"], str) and req["endpoint"].startswith('/'):
            req_copy["endpoint"] = base_url + req["endpoint"]
            updated_requests.append(req_copy)

    # Test each request
    results = []
    for req in updated_requests:
        if req["endpoint"] is False:
            results.append({
                "name": req["name"],
                "status_code": "SKIPPED",
                "result": "Service endpoint not found",
                "auth_required": req["auth_required"],
                "endpoint": None
            })
            continue

        url = req["endpoint"]
        response = send_request(req, url, timeout)

        # Determine result message based on response and fault type
        fault_info = response.get("fault_info", {})
        fault_type = fault_info.get('fault_type', 'other')

        # Check if this indicates unauthenticated access
        # Success (200 OK) or parameter validation errors both indicate the service is accessible
        is_accessible = response["success"] or (fault_type == 'param_validation')

        if is_accessible and req["auth_required"]:
            # Security issue: service should require auth but accepts unauthenticated requests
            if response["success"]:
                result_msg = "SECURITY ISSUE: responded without authentication!"
            else:
                result_msg = f"SECURITY ISSUE: accessible without authentication (param validation error: {fault_info.get('fault_code', 'unknown')})"
            security_issue = True
        elif is_accessible and not req["auth_required"]:
            # Expected behavior: service designed to be unauthenticated
            result_msg = "responded as expected (unauthenticated by design)"
            security_issue = False
        elif response["status_code"] == 401 or fault_type == 'auth':
            # Properly secured: requires authentication
            result_msg = "requires authentication (secure)"
            security_issue = False
        else:
            # Other failures (not implemented, network errors, etc.)
            if fault_type == 'not_implemented':
                result_msg = f"not implemented: {fault_info.get('fault_reason', 'unknown')[:80]}"
            else:
                result_msg = f"failed: {response['content'][:50]}..."
            security_issue = False

        parsed_uris = parse_uris(response["content"]) if urls_only else []

        results.append({
            "name": req["name"],
            "status_code": response["status_code"] or "ERROR",
            "result": result_msg,
            "auth_required": req["auth_required"],
            "endpoint": url,
            "security_issue": security_issue,
            "fault_info": fault_info,
            "response_content": response["content"] if verbose or len(response["content"]) < 1000 else response["content"][:1000] + "..." if not urls_only else str(parsed_uris),
            "parsed_uris": parsed_uris
        })

    # Group results by status code for summary
    from collections import defaultdict
    grouped_results = defaultdict(list)
    security_issues = []

    for result in results:
        grouped_results[result["status_code"]].append(result)
        if result.get("security_issue", False):
            security_issues.append(result)

    return {
        'services_discovered': True,
        'endpoints_discovered': endpoints,
        'total_tests': len(results),
        'security_issues': security_issues,
        'results_by_status': dict(grouped_results),
        'all_results': results
    }


def run_auth_scan(config: 'ToolConfig') -> 'ToolResult':
    """Run the authentication scan."""
    import time
    start_time = time.time()

    try:
        test_all = config.custom_args.get('all', False)
        timeout = config.timeout or 5.0
        verbose = config.verbose
        urls_only = config.custom_args.get('u', False)

        # Perform scanning
        scan_result = scan_onvif_device(config.input_path, test_all, timeout, verbose, urls_only)

        execution_time = time.time() - start_time

        return ToolResult(
            success=scan_result.get('services_discovered', False),
            data=scan_result,
            errors=[scan_result.get('error')] if 'error' in scan_result else [],
            metadata={
                'total_tests': scan_result.get('total_tests', 0),
                'security_issues_count': len(scan_result.get('security_issues', [])),
                'endpoints_discovered': len(scan_result.get('endpoints_discovered', {})),
                'target_url': config.input_path,
                'test_all': test_all,
                'urls_only': urls_only
            },
            execution_time=execution_time
        )

    except Exception as e:
        execution_time = time.time() - start_time
        return ToolResult(
            success=False,
            data=None,
            errors=[str(e)],
            metadata={'target_url': config.input_path},
            execution_time=execution_time
        )
