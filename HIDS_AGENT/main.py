import time
import threading

from monitor import get_system_data

from api_client import (
    send_data,
    send_file_event,
    send_security_event
)

from fileMonitor import start_file_monitor

from loginMonitor import LoginMonitor

from config import (
    INTERVAL,
    SECURITY_EVENT_INTERVAL,
    HOST_ID
)


# =========================================================
# FILE MONITOR CONFIGURATION
# =========================================================

FILE_MONITOR_PATH = (
    r"D:\Users\SACHIN\Visual code\FY Project\HIDS_AGENT\test_monitor"
)


# =========================================================
# FILE EVENT CALLBACK
# =========================================================

def handle_file_event(event):

    # Add Host ID
    event["hostId"] = HOST_ID

    # Send file event to backend
    send_file_event(event)


# =========================================================
# LOGIN / SECURITY EVENT MONITOR
# =========================================================

def security_monitor_loop():

    monitor = None

    try:

        print()
        print("====================================")
        print("   SECURITY EVENT MONITOR STARTING")
        print("====================================")

        monitor = LoginMonitor()

        print("Security Event Monitor: Started")

        while True:

            try:

                events = monitor.get_events()

                for event in events:

                    # Add Host ID
                    event["hostId"] = HOST_ID

                    print()
                    print("========== SECURITY EVENT ==========")

                    print(
                        "Event Type:",
                        event["eventType"]
                    )

                    print(
                        "Event ID:",
                        event["eventId"]
                    )

                    print(
                        "Username:",
                        event["username"]
                    )

                    print(
                        "Domain:",
                        event["domain"]
                    )

                    print(
                        "Logon Type:",
                        event["logonType"]
                    )

                    print(
                        "IP Address:",
                        event["ipAddress"]
                    )

                    print(
                        "Workstation:",
                        event["workstationName"]
                    )

                    print(
                        "Authentication:",
                        event[
                            "authenticationPackageName"
                        ]
                    )

                    print(
                        "Record ID:",
                        event["recordId"]
                    )

                    print(
                        "Timestamp:",
                        event["timestamp"]
                    )

                    print("====================================")

                    # Send event to backend
                    send_security_event(event)

                time.sleep(
                    SECURITY_EVENT_INTERVAL
                )

            except Exception as error:

                print(
                    "Security Monitor Error:",
                    error
                )

                time.sleep(
                    SECURITY_EVENT_INTERVAL
                )

    except Exception as error:

        print(
            "Security Monitor Startup Error:",
            error
        )

    finally:

        if monitor is not None:

            monitor.close()


# =========================================================
# START AI-HIDS AGENT
# =========================================================

print("====================================")
print("      AI-HIDS AGENT STARTED")
print("====================================")


# =========================================================
# START FILE MONITOR
# =========================================================

file_monitor_thread = threading.Thread(
    target=start_file_monitor,
    args=(
        FILE_MONITOR_PATH,
        handle_file_event
    ),
    daemon=True
)

file_monitor_thread.start()


# =========================================================
# START SECURITY / LOGIN MONITOR
# =========================================================

security_monitor_thread = threading.Thread(
    target=security_monitor_loop,
    daemon=True
)

security_monitor_thread.start()


# =========================================================
# MAIN SYSTEM MONITORING LOOP
# =========================================================

while True:

    try:

        data = get_system_data()

        # Add Host ID
        data["hostId"] = HOST_ID

        print()
        print("------------------------------------")
        print("Host:", data["hostname"])
        print("CPU:", data["cpu"], "%")
        print("RAM:", data["ram"], "%")
        print("Disk:", data["disk"], "%")
        print("Processes:", data["processCount"])
        print("------------------------------------")

        # Send normal system/process data
        send_data(data)

        # Wait before next monitoring cycle
        time.sleep(INTERVAL)

    except KeyboardInterrupt:

        print()
        print("AI-HIDS Agent Stopped.")
        break

    except Exception as error:

        print(
            "Agent Error:",
            error
        )

        time.sleep(INTERVAL)