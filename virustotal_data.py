import requests
class VirusTotal:
    def __init__(self):
        self.ip_validate = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        self.url_validator = 'https://www.virustotal.com/vtapi/v2/url/report'
        self.file_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
        
        self.apikey='6711ca0055bde3a036a1294b3c2cb35fcac76b38a1616ac191e6216b0195ce7e'
        # params = {'apikey':'','ip':self.ip_address}
    def get_ip_data(self,ip):
        # print("In Virustotal get ip data method",ip,"Api key", self.apikey)
        params = {'apikey':self.apikey,'ip':ip}
        return requests.get(self.ip_validate,params)

    def get_URL_data(self,url):
        params = {'apikey':self.apikey,'resource':url}
        return requests.get(self.url_validator,params)

    def file_scan(self,file_location):
        params = {'apikey': self.apikey}
        # files = {'file': ('myfile.exe', open(file_location, 'rb'))}
        file=open(file_location, 'rb')
        return requests.post(self.file_scan,params={
            'apikey':self.apikey
        },files={'file':file})

    def file_report(self,scan_id):
        return requests.get("https://www.virustotal.com/vtapi/v2/file/report", params={
            'apikey':self.apikey,
            'resource':scan_id
        }).json()
