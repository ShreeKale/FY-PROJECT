import time

from loginMonitor import LoginMonitor


print("====================================")
print("      AI-HIDS LOGIN MONITOR")
print("====================================")


monitor = None


try:

    monitor = LoginMonitor()

    print("====================================")
    print("      LOGIN MONITOR STARTED")
    print("====================================")
    print()
    print("Monitoring Windows Security events...")
    print("Press Ctrl+C to stop.")
    print()

    while True:

        events = monitor.get_events()

        for event in events:

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
                event["authenticationPackageName"]
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

        time.sleep(2)


except KeyboardInterrupt:

    print()
    print("Stopping Login Monitor...")


except Exception as error:

    print()
    print("Login Monitor Error:")
    print(error)


finally:

    if monitor is not None:
        monitor.close()