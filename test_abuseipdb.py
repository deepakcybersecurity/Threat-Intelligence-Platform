import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

url = "https://api.abuseipdb.com/api/v2/check"

params = {
    "ipAddress": "8.8.8.8",
    "maxAgeInDays": 90
}

headers = {
    "Accept": "application/json",
    "Key": API_KEY
}

response = requests.get(
    url,
    headers=headers,
    params=params
)

print("Status Code:", response.status_code)
print("Response:")
print(response.json())