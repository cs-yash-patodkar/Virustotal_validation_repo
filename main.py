from url_class import URL
from ip_class import IP
import traceback
import logging
from file_class import File

logging.basicConfig(filename="newfile.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')
logger = logging.getLogger()
 
# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)

flag = True

while flag:
    try:
        print("\n1 Validate IP ")
        print("2 Validate URL ")
        print("3 Validate File ")
        print("4 Exit")
        choice = int(input("Enter Your Choice \n"))
        if choice == 1:
            ip = input("Enter a valid IP address \n")

            ip_result = IP(ip)
            # logger.info("User Selected Validate IP Option")
            print("{:.2f}".format(ip_result.check_ip_legitimacy()),
                  "% of the detected URLs have found this IP malicious")

        elif choice == 2:
            url = input("Enter a valid URL\n")
            # url_result = URL(url)
            
            # logger.info("User Selected Validate URL Option")
            print("{:.2f}".format(URL(url).check_legitimacy()),
                  "% of the sites have found this URL malicious")

        elif choice == 3:
            location = input("Enter a valid file path")
            # logger.info("User has selected validate file option")
            print((File(location).check_file_legitimacy()),
             "% of the sites have found this File malicious")

        elif choice == 4:
            flag = False
        else:
            print("Enter Correct Choice\n")
    except AssertionError as ex:
        print("Enter valid credentials")
    except Exception as ex:
        # print(ex.with_traceback(tb))
        traceback.print_exc()
