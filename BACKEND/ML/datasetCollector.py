import requests
import csv
import os
import time
from datetime import datetime, timezone


# ============================================================
# CONFIGURATION
# ============================================================

HOST_ID = "PC-001"

BASE_URL = "http://localhost:5000"

HOST_API = f"{BASE_URL}/api/host/{HOST_ID}"
PROCESS_API = f"{BASE_URL}/api/processes/{HOST_ID}"
SECURITY_API = f"{BASE_URL}/api/security-events/{HOST_ID}"
FILE_API = f"{BASE_URL}/api/file-events/{HOST_ID}"

DATASET_FILE = "hids_dataset.csv"

COLLECTION_INTERVAL = 5


# ============================================================
# DATASET COLUMNS
# ============================================================

FIELDS = [
    "timestamp",

    "cpu_usage",
    "ram_usage",
    "disk_usage",
    "process_count",

    "new_processes",
    "terminated_processes",

    "login_success",
    "login_failed",
    "logoff_events",

    "file_created",
    "file_modified",
    "file_deleted",
    "file_renamed"
]


# ============================================================
# STATE
# ============================================================

last_process_timestamp = None
last_security_timestamp = None
last_file_timestamp = None


# ============================================================
# CSV INITIALIZATION
# ============================================================

def initialize_dataset():

    if not os.path.exists(DATASET_FILE):

        with open(
            DATASET_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=FIELDS
            )

            writer.writeheader()

        print(f"[+] Created dataset: {DATASET_FILE}")

    else:

        print(f"[+] Dataset already exists: {DATASET_FILE}")


# ============================================================
# API REQUEST
# ============================================================

def get_json(url):

    try:

        response = requests.get(
            url,
            timeout=5
        )

        response.raise_for_status()

        return response.json()

    except Exception as error:

        print(f"[!] API error: {url}")
        print(f"    {error}")

        return None


# ============================================================
# TIMESTAMP CONVERSION
# ============================================================

def parse_timestamp(value):

    if not value:
        return None

    try:

        value = str(value)

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        parsed = datetime.fromisoformat(value)

        # Convert timezone-aware datetime to UTC
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(
                tzinfo=None
            )

        return parsed

    except Exception:

        return None


# ============================================================
# PROCESS EVENT COUNTING
# ============================================================

def count_process_events(processes, last_timestamp):

    new_count = 0
    terminated_count = 0

    newest_timestamp = last_timestamp

    for process in processes:

        # ----------------------------------------------------
        # NEW PROCESS
        # ----------------------------------------------------

        first_seen = parse_timestamp(
            process.get("firstSeen")
        )

        if first_seen is not None:

            if (
                last_timestamp is None
                or first_seen > last_timestamp
            ):

                new_count += 1

                if (
                    newest_timestamp is None
                    or first_seen > newest_timestamp
                ):

                    newest_timestamp = first_seen


        # ----------------------------------------------------
        # TERMINATED PROCESS
        # ----------------------------------------------------

        terminated_at = parse_timestamp(
            process.get("terminatedAt")
        )

        if terminated_at is not None:

            if (
                last_timestamp is None
                or terminated_at > last_timestamp
            ):

                terminated_count += 1

                if (
                    newest_timestamp is None
                    or terminated_at > newest_timestamp
                ):

                    newest_timestamp = terminated_at


    return (
        new_count,
        terminated_count,
        newest_timestamp
    )


# ============================================================
# SECURITY / FILE EVENT COUNTING
# ============================================================

def count_new_events(
    events,
    event_type,
    last_timestamp
):

    count = 0
    newest_timestamp = last_timestamp

    for event in events:

        timestamp = parse_timestamp(
            event.get("timestamp")
        )

        if timestamp is None:
            continue

        if (
            last_timestamp is not None
            and timestamp <= last_timestamp
        ):
            continue

        current_type = str(
            event.get("eventType", "")
        ).upper()

        if current_type == event_type.upper():

            count += 1

            if (
                newest_timestamp is None
                or timestamp > newest_timestamp
            ):

                newest_timestamp = timestamp


    return count, newest_timestamp


# ============================================================
# COLLECT ONE DATA POINT
# ============================================================

def collect_data_point():

    global last_process_timestamp
    global last_security_timestamp
    global last_file_timestamp


    # ========================================================
    # HOST DATA
    # ========================================================

    host_data = get_json(HOST_API)

    if not host_data or not host_data.get("success"):

        print("[!] Host data unavailable")
        print("[!] Dataset sample skipped")

        return


    host = host_data.get("host", {})

    cpu = float(
        host.get("cpu", 0) or 0
    )

    ram = float(
        host.get("ram", 0) or 0
    )

    disk = float(
        host.get("disk", 0) or 0
    )

    process_count = int(
        host.get("processCount", 0) or 0
    )


    # ========================================================
    # PROCESS DATA
    # ========================================================

    process_data = get_json(PROCESS_API)

    processes = []

    if (
        process_data
        and process_data.get("success")
    ):

        processes = process_data.get(
            "processes",
            []
        )


    (
        new_processes,
        terminated_processes,
        process_timestamp
    ) = count_process_events(
        processes,
        last_process_timestamp
    )


    if process_timestamp:

        last_process_timestamp = process_timestamp


    # ========================================================
    # SECURITY DATA
    # ========================================================

    security_data = get_json(SECURITY_API)

    security_events = []

    if (
        security_data
        and security_data.get("success")
    ):

        security_events = security_data.get(
            "events",
            []
        )


    login_success, security_ts_1 = count_new_events(
        security_events,
        "LOGIN_SUCCESS",
        last_security_timestamp
    )

    login_failed, security_ts_2 = count_new_events(
        security_events,
        "LOGIN_FAILED",
        last_security_timestamp
    )

    logoff_events, security_ts_3 = count_new_events(
        security_events,
        "LOGOFF",
        last_security_timestamp
    )


    security_timestamps = [
        value
        for value in [
            security_ts_1,
            security_ts_2,
            security_ts_3
        ]
        if value is not None
    ]


    if security_timestamps:

        last_security_timestamp = max(
            security_timestamps
        )


    # ========================================================
    # FILE DATA
    # ========================================================

    file_data = get_json(FILE_API)

    file_events = []

    if (
        file_data
        and file_data.get("success")
    ):

        file_events = file_data.get(
            "events",
            []
        )


    file_created, file_ts_1 = count_new_events(
        file_events,
        "FILE_CREATED",
        last_file_timestamp
    )

    file_modified, file_ts_2 = count_new_events(
        file_events,
        "FILE_MODIFIED",
        last_file_timestamp
    )

    file_deleted, file_ts_3 = count_new_events(
        file_events,
        "FILE_DELETED",
        last_file_timestamp
    )

    file_renamed, file_ts_4 = count_new_events(
        file_events,
        "FILE_RENAMED",
        last_file_timestamp
    )


    file_timestamps = [
        value
        for value in [
            file_ts_1,
            file_ts_2,
            file_ts_3,
            file_ts_4
        ]
        if value is not None
    ]


    if file_timestamps:

        last_file_timestamp = max(
            file_timestamps
        )


    # ========================================================
    # CREATE DATASET ROW
    # ========================================================

    row = {

        "timestamp":
            datetime.now().isoformat(),

        "cpu_usage":
            round(cpu, 2),

        "ram_usage":
            round(ram, 2),

        "disk_usage":
            round(disk, 2),

        "process_count":
            process_count,

        "new_processes":
            new_processes,

        "terminated_processes":
            terminated_processes,

        "login_success":
            login_success,

        "login_failed":
            login_failed,

        "logoff_events":
            logoff_events,

        "file_created":
            file_created,

        "file_modified":
            file_modified,

        "file_deleted":
            file_deleted,

        "file_renamed":
            file_renamed
    }


    # ========================================================
    # SAVE
    # ========================================================

    with open(
        DATASET_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )

        writer.writerow(row)


    # ========================================================
    # DISPLAY
    # ========================================================

    print()
    print("=" * 60)

    print(
        f"Dataset Sample: {row['timestamp']}"
    )

    print(
        f"CPU: {row['cpu_usage']}%"
    )

    print(
        f"RAM: {row['ram_usage']}%"
    )

    print(
        f"Disk: {row['disk_usage']}%"
    )

    print(
        f"Processes: {row['process_count']}"
    )

    print(
        f"New Processes: {row['new_processes']}"
    )

    print(
        f"Terminated Processes: "
        f"{row['terminated_processes']}"
    )

    print(
        f"Login Success: "
        f"{row['login_success']}"
    )

    print(
        f"Login Failed: "
        f"{row['login_failed']}"
    )

    print(
        f"Logoff: "
        f"{row['logoff_events']}"
    )

    print(
        f"Files Created: "
        f"{row['file_created']}"
    )

    print(
        f"Files Modified: "
        f"{row['file_modified']}"
    )

    print(
        f"Files Deleted: "
        f"{row['file_deleted']}"
    )

    print(
        f"Files Renamed: "
        f"{row['file_renamed']}"
    )

    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("==============================================")
    print("       AI-HIDS DATASET COLLECTOR")
    print("==============================================")
    print()

    print(f"Host ID : {HOST_ID}")
    print(f"API     : {BASE_URL}")
    print(f"Dataset : {DATASET_FILE}")
    print(f"Interval: {COLLECTION_INTERVAL} seconds")

    print()

    initialize_dataset()

    print("[+] Dataset collection started")
    print("[+] Press CTRL+C to stop")
    print()


    while True:

        try:

            collect_data_point()

            time.sleep(
                COLLECTION_INTERVAL
            )

        except KeyboardInterrupt:

            print()
            print("[+] Dataset collection stopped")

            break

        except Exception as error:

            print(
                f"[!] Collector error: {error}"
            )

            time.sleep(
                COLLECTION_INTERVAL
            )


if __name__ == "__main__":
    main()