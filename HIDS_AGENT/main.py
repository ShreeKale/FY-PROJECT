import time

from monitor import get_system_data

from api_client import send_data

from config import INTERVAL


print("AI-HIDS Agent Started...")


while True:

    data = get_system_data()

    print(data)

    send_data(data)

    time.sleep(INTERVAL)