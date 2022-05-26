import requests
import validators
from virustotal_data import VirusTotal
import os 

class File:
    def __init__(self, file_location):
        assert os.path.exists(file_location)
        self.file_location=file_location
    
    def check_file_legitimacy(self):
        vt=VirusTotal()
        scan_id=vt.file_scan(self.file_location).json()["scan_id"]
        print("File has been Uploaded, wait for a few seconds to get the result")
        sleep(20)
        data = vt.file_report(scan_id)

        total=URL_data.json().get('total')
        positives = URL_data.json().get("positives")
        return positives*100/total
        
