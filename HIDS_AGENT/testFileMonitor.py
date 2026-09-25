import os

from fileMonitor import start_file_monitor


folder = r"D:\Users\SACHIN\Visual code\FY Project\HIDS_AGENT\test_monitor"


def test_file_event(event):

    print("\n========== TEST FILE EVENT ==========")
    print(event)
    print("=====================================")


# Create folder if it doesn't exist
os.makedirs(folder, exist_ok=True)


# Start file monitor
start_file_monitor(
    folder,
    test_file_event
)