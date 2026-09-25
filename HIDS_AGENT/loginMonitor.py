import time
import xml.etree.ElementTree as ET

import win32evtlog


SECURITY_LOG = "Security"

# Windows Security Event IDs we want to monitor
SECURITY_EVENT_IDS = {
    4624: "LOGIN_SUCCESS",
    4625: "LOGIN_FAILED",
    4634: "LOGOFF",
    4647: "USER_LOGOFF"
}

# XML namespace used by Windows Event Log
EVENT_NAMESPACE = {
    "evt": "http://schemas.microsoft.com/win/2004/08/events/event"
}


class LoginMonitor:

    def __init__(self):

        self.channel = SECURITY_LOG

        print("Opening Windows Security Event Log...")

        # Get the latest record ID first.
        # This prevents the monitor from processing old events.
        self.last_record_id = self.get_latest_record_id()

        print(
            f"Starting from Security Event Record ID: "
            f"{self.last_record_id}"
        )

    # ---------------------------------------------------------
    # Get latest Security Event Record ID
    # ---------------------------------------------------------

    def get_latest_record_id(self):

        query = """
        *[
            System[
                (
                    EventID=4624 or
                    EventID=4625 or
                    EventID=4634 or
                    EventID=4647
                )
            ]
        ]
        """

        try:

            query_handle = win32evtlog.EvtQuery(
                self.channel,
                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryReverseDirection,
                query
            )

            events = win32evtlog.EvtNext(
                query_handle,
                1,
                0
            )

            if not events:
                return 0

            xml = win32evtlog.EvtRender(
                events[0],
                win32evtlog.EvtRenderEventXml
            )

            root = ET.fromstring(xml)

            record_id_element = root.find(
                "./evt:System/evt:EventRecordID",
                EVENT_NAMESPACE
            )

            if record_id_element is not None:
                return int(record_id_element.text)

            return 0

        except Exception as error:

            print(
                "Error getting latest event record:",
                error
            )

            return 0

    # ---------------------------------------------------------
    # Get new login/security events
    # ---------------------------------------------------------

    def get_events(self):

        new_events = []

        # Only retrieve the security events we care about.
        query = """
        *[
            System[
                (
                    EventID=4624 or
                    EventID=4625 or
                    EventID=4634 or
                    EventID=4647
                )
            ]
        ]
        """

        try:

            query_handle = win32evtlog.EvtQuery(
                self.channel,
                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryForwardDirection,
                query
            )

            while True:

                events = win32evtlog.EvtNext(
                    query_handle,
                    50,
                    0
                )

                if not events:
                    break

                for event_handle in events:

                    try:

                        event_xml = win32evtlog.EvtRender(
                            event_handle,
                            win32evtlog.EvtRenderEventXml
                        )

                        event = self.parse_event_xml(
                            event_xml
                        )

                        if event is None:
                            continue

                        record_id = event["recordId"]

                        # Ignore events already processed
                        if record_id <= self.last_record_id:
                            continue

                        self.last_record_id = max(
                            self.last_record_id,
                            record_id
                        )

                        new_events.append(event)

                    except Exception as error:

                        print(
                            "Error parsing security event:",
                            error
                        )

            # Sort events in chronological record order
            new_events.sort(
                key=lambda event: event["recordId"]
            )

            return new_events

        except Exception as error:

            print(
                "Error reading Security Event Log:",
                error
            )

            return []

    # ---------------------------------------------------------
    # Parse Windows Event XML
    # ---------------------------------------------------------

    def parse_event_xml(self, event_xml):

        try:

            root = ET.fromstring(event_xml)

            # -------------------------------------------------
            # Event ID
            # -------------------------------------------------

            event_id_element = root.find(
                "./evt:System/evt:EventID",
                EVENT_NAMESPACE
            )

            if event_id_element is None:
                return None

            event_id = int(
                event_id_element.text
            )

            if event_id not in SECURITY_EVENT_IDS:
                return None

            event_type = SECURITY_EVENT_IDS[
                event_id
            ]

            # -------------------------------------------------
            # Record ID
            # -------------------------------------------------

            record_id_element = root.find(
                "./evt:System/evt:EventRecordID",
                EVENT_NAMESPACE
            )

            if record_id_element is None:
                return None

            record_id = int(
                record_id_element.text
            )

            # -------------------------------------------------
            # Timestamp
            # -------------------------------------------------

            time_created = root.find(
                "./evt:System/evt:TimeCreated",
                EVENT_NAMESPACE
            )

            timestamp = None

            if time_created is not None:

                timestamp = time_created.get(
                    "SystemTime"
                )

            # -------------------------------------------------
            # Extract EventData fields
            # -------------------------------------------------

            event_data = {}

            for data_element in root.findall(
                "./evt:EventData/evt:Data",
                EVENT_NAMESPACE
            ):

                field_name = data_element.get(
                    "Name"
                )

                field_value = data_element.text

                if field_value is None:
                    field_value = "-"

                event_data[field_name] = field_value

            # -------------------------------------------------
            # Requested fields
            # -------------------------------------------------

            username = event_data.get(
                "TargetUserName",
                "-"
            )

            domain = event_data.get(
                "TargetDomainName",
                "-"
            )

            logon_type = event_data.get(
                "LogonType",
                "-"
            )

            ip_address = event_data.get(
                "IpAddress",
                "-"
            )

            workstation = event_data.get(
                "WorkstationName",
                "-"
            )

            authentication_package = event_data.get(
                "AuthenticationPackageName",
                "-"
            )

            # -------------------------------------------------
            # Clean values
            # -------------------------------------------------

            username = self.clean_value(
                username
            )

            domain = self.clean_value(
                domain
            )

            logon_type = self.clean_value(
                logon_type
            )

            ip_address = self.clean_value(
                ip_address
            )

            workstation = self.clean_value(
                workstation
            )

            authentication_package = self.clean_value(
                authentication_package
            )

            # -------------------------------------------------
            # Build final event
            # -------------------------------------------------

            security_event = {

                "eventType": event_type,

                "eventId": event_id,

                "username": username,

                "domain": domain,

                "logonType": logon_type,

                "ipAddress": ip_address,

                "workstationName": workstation,

                "authenticationPackageName":
                    authentication_package,

                "recordId": record_id,

                "timestamp": timestamp
            }

            return security_event

        except Exception as error:

            print(
                "XML parsing error:",
                error
            )

            return None

    # ---------------------------------------------------------
    # Clean Windows event values
    # ---------------------------------------------------------

    def clean_value(self, value):

        if value is None:
            return "-"

        value = str(value).strip()

        if value == "":
            return "-"

        return value

    # ---------------------------------------------------------
    # Close monitor
    # ---------------------------------------------------------

    def close(self):

        print(
            "\nLogin monitor stopped."
        )