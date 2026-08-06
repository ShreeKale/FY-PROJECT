import psutil
import socket
import platform
from datetime import datetime


def get_system_data():

    cpu = psutil.cpu_percent(interval=1)

    ram = psutil.virtual_memory().percent

    disk = psutil.disk_usage("/").percent

    hostname = socket.gethostname()

    os_name = platform.system()

    process_list = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_list.append({
                "pid": proc.info['pid'],
                "name": proc.info['name']
            })
        except:
            pass

    return {
        "hostname": hostname,
        "os": os_name,
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "processes": process_list,
        "timestamp": datetime.now().isoformat()
    }