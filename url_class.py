import requests
from virustotal_data import VirusTotal 
import validators

class URL:
    def __init__(self, url):
        assert validators.domain(url)
        self.url=url

    def check_legitimacy(self):

        URL_data = VirusTotal().get_URL_data(self.url)
        # Getting total
        total=URL_data.json().get('total')
        positives = URL_data.json().get("positives")


        # calculating the %
        # print("{:.2f}".format(positives*100/total),"% of the sites have found this URL malicious")
        return positives*100/total