import requests
import validators
from virustotal_data import VirusTotal 
class IP:
    def __init__(self, ip_address):
        assert validators.ip_address.ipv4(ip_address) or validators.ip_address.ipv6(ip_address)
        self.ip_address=ip_address
    
    def check_ip_legitimacy (self):
        vt = VirusTotal()
        # print("API_",vt.apikey)
        # virus_total_data = VirusTotal().get_ip_data(self.ip_address)
        virus_total_data = vt.get_ip_data(self.ip_address)
        detected_urls=virus_total_data.json().get("detected_urls")
        positives = 0
        total =0
        for i in range(len(detected_urls)):
            positives += detected_urls[i].get("positives")
            total += detected_urls[i].get("total")
        # print("{:.2f}".format(positives*100/total),"% of the sites have found this URL malicious")
        return positives*100/total
