from distutils.command.config import config
import requests
import logging
# from file_class import File
from configparser import ConfigParser

config = ConfigParser()

file='config.ini'
config.read(file)

logging.basicConfig(filename="newfile.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')
logger = logging.getLogger()
 
# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)

class VirusTotal:
    def __init__(self):
        self.ip_validate = config["url"]['ip_validate']
        self.url_validator = config['url']["url_validator"]
        self.file_scan = config['url']['file_scan']
        
        self.apikey=config['api']['apikey']
        # params = {'apikey':'','ip':self.ip_address}
    def get_ip_data(self,ip):
        # print("In Virustotal get ip data method",ip,"Api key", self.apikey)
        params = {'apikey':self.apikey,'ip':ip}
        return requests.get(self.ip_validate,params)

    def get_URL_data(self,url):
        # logger.info("Chc")
        params = {'apikey':self.apikey,'resource':url}
        return requests.get(self.url_validator,params)

    def file_scan_(self,file_location):
        # params = {'apikey': self.apikey}
        # files = {'file': ('myfile.exe', open(file_location, 'rb'))}
        # logger.info("Uploading file to Virus total")
        file=open(file_location, 'rb')
        return requests.post(self.file_scan,params={
            'apikey':self.apikey
        },files={'file':file})

    def file_report_(self,scan_id):
        return requests.get("https://www.virustotal.com/vtapi/v2/file/report", params={
            'apikey':self.apikey,
            'resource':scan_id
        }).json()
