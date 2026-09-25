import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileMonitorHandler(FileSystemEventHandler):

    def __init__(self, event_callback):
        super().__init__()
        self.event_callback = event_callback

    def send_event(self, event_type, path, old_path=None):

        # Ignore directories
        if os.path.isdir(path):
            return

        event = {
            "eventType": event_type,
            "fileName": os.path.basename(path),
            "filePath": path,
            "oldPath": old_path
        }

        print("\n========== FILE EVENT ==========")
        print(f"Event Type : {event_type}")
        print(f"File Name  : {event['fileName']}")
        print(f"File Path  : {event['filePath']}")
        print(f"Old Path   : {event['oldPath']}")
        print("================================")

        # Send event to the HIDS API client
        self.event_callback(event)

    def on_created(self, event):
        self.send_event(
            "FILE_CREATED",
            event.src_path
        )

    def on_modified(self, event):
        self.send_event(
            "FILE_MODIFIED",
            event.src_path
        )

    def on_deleted(self, event):
        self.send_event(
            "FILE_DELETED",
            event.src_path
        )

    def on_moved(self, event):
        self.send_event(
            "FILE_RENAMED",
            event.dest_path,
            event.src_path
        )


def start_file_monitor(folder, event_callback):

    if not os.path.exists(folder):
        print(f"File monitor folder does not exist: {folder}")
        return

    handler = FileMonitorHandler(event_callback)

    observer = Observer()

    observer.schedule(
        handler,
        folder,
        recursive=True
    )

    observer.start()

    print("================================")
    print("FILE MONITOR STARTED")
    print("Monitoring:")
    print(folder)
    print("================================")

    try:
        # Keep watchdog observer alive
        observer.join()

    except KeyboardInterrupt:
        observer.stop()
        observer.join()