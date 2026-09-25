import requests

from config import (
    API_URL,
    FILE_EVENT_URL,
    SECURITY_EVENT_URL
)


# =========================================================
# NORMAL HOST + PROCESS TELEMETRY
# =========================================================

def send_data(data):

    try:

        response = requests.post(
            API_URL,
            json=data,
            timeout=10
        )

        if response.status_code == 200:

            print("Server: Connected")

        else:

            print(
                "Server Error:",
                response.status_code,
                response.text
            )

    except requests.exceptions.ConnectionError:

        print(
            "Connection Error: Backend server is not running."
        )

    except requests.exceptions.Timeout:

        print(
            "Connection Error: Server timeout."
        )

    except Exception as error:

        print(
            "Connection Error:",
            error
        )


# =========================================================
# FILE EVENT
# =========================================================

def send_file_event(event):

    try:

        file_event_data = {
            "hostId": event.get("hostId"),
            "event": event
        }

        response = requests.post(
            FILE_EVENT_URL,
            json=file_event_data,
            timeout=10
        )

        if response.status_code == 200:

            print("File Event: Sent to server")

        else:

            print(
                "File Event Server Error:",
                response.status_code,
                response.text
            )

    except requests.exceptions.ConnectionError:

        print(
            "File Event Error: Backend server is not running."
        )

    except requests.exceptions.Timeout:

        print(
            "File Event Error: Server timeout."
        )

    except Exception as error:

        print(
            "File Event Error:",
            error
        )


# =========================================================
# SECURITY / LOGIN EVENT
# =========================================================

def send_security_event(event):

    try:

        security_event_data = {
            "hostId": event.get("hostId"),
            "event": event
        }

        response = requests.post(
            SECURITY_EVENT_URL,
            json=security_event_data,
            timeout=10
        )

        if response.status_code == 200:

            print(
                "Security Event: Sent to server"
            )

        else:

            print(
                "Security Event Server Error:",
                response.status_code,
                response.text
            )

    except requests.exceptions.ConnectionError:

        print(
            "Security Event Error: Backend server is not running."
        )

    except requests.exceptions.Timeout:

        print(
            "Security Event Error: Server timeout."
        )

    except Exception as error:

        print(
            "Security Event Error:",
            error
        )