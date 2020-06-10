


## - Prepare patch information 

(1) Download CVE information from [NVD](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) where offers a vulnerability data feed using the JSON format and store it in nvdcve-json. 

(2) Download [patch information](https://drive.google.com/file/d/1gP3do0S7lXzXsAnBQbS5QA6hoc3vNaRt/view?usp=sharing) which is collected by our team and store it in nvd_data.


## - Obtain CVE information and patch information  


```bash software_gen_cve.sh```

software_gen_cve.sh  calls cve.py and apply.sh


According to the software version information in SoftwareList.csv, software_gen_cve.sh generate cve IDs that affect the software and further find the function name and file name in the the CVE information.

- cve.py

Output the vulnerability ID corresponding to the software, and store the result in software-Tmpoutput

- apply.sh

Output file path and function name, the result is stored in searchResults


