import requests
from requests.utils import default_headers

url = "http://192.168.0.184:6006/"
headers = default_headers()
headers.update(
    {
        'User-Agent': 'Teapare'
    }
)
print("A")
# print(requests.get("http://192.168.0.184:8080/metadata/1.root.json").text)
# print(requests.post(url, headers=headers, files=[('12345.exe', open("C:/Users/teapa/Downloads/Cardes/Cardes.exe", 'rb'))]).text)