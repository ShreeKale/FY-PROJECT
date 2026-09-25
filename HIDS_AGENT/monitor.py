import psutil
import socket
import platform
from datetime import datetime


def get_process_data():

    process_list = []

    for proc in psutil.process_iter(
        ['pid', 'name', 'exe', 'username', 'create_time']
    ):

        try:

            process_info = proc.info

            process_list.append({
                "pid": process_info.get("pid"),
                "name": process_info.get("name") or "Unknown",
                "executablePath": process_info.get("exe") or "",
                "user": process_info.get("username") or "",
                "createTime": process_info.get("create_time")
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

        except Exception:
            continue

    return process_list


def get_system_data():

    # ================= SYSTEM =================

    cpu = psutil.cpu_percent(interval=1)

    ram = psutil.virtual_memory().percent

    disk = psutil.disk_usage("/").percent

    hostname = socket.gethostname()

    os_name = platform.system()

    # ================= PROCESSES =================

    process_list = get_process_data()

    # ================= FINAL DATA =================

    return {
        "hostname": hostname,
        "os": os_name,

        "cpu": cpu,
        "ram": ram,
        "disk": disk,

        "processCount": len(process_list),

        "processes": process_list,

        "timestamp": datetime.now().isoformat()
    }