import requests
from config import API_URL


def send_data(data):

    try:

        response = requests.post(API_URL, json=data)

        print("Server:", response.status_code)

    except Exception as e:

        print("Connection Error:", e)