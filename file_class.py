import requests
import validators
from virustotal_data import VirusTotal
import os 
import time

class File:
    def __init__(self, file_location):
        assert os.path.exists(file_location)
        self.file_location=file_location
    
    def check_file_legitimacy(self):
        vt=VirusTotal()
        scan_id=vt.file_scan_(self.file_location).json()["scan_id"]
        print("File has been Uploaded, wait for a few seconds to get the result")
        
        number_of_hits=0
        while True:
            data = vt.file_report_(scan_id)
            number_of_hits+=1
            if(number_of_hits==2):
                x=input("It is taking longer than usual, enter y to continue")
                if(x=="y"):
                    break
                else:
                    continue
            if data["response_code"]==-2:
                time.sleep(20)
                print("Please wait, response is on the way")
                continue
            if data['response_code']==1:
                break

        total=data.json().get('total')
        positives = data.json().get("positives")
        return positives*100/total
        
