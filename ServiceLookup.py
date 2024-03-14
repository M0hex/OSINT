from ShodanSearch import ShodanLookup
from PortScan import *
import re,requests,socket

defaults = {
"smtp":[25],
"dns":[53],
"ns":[53],
"web":[80,443],
"www":[80,443],
"api":[80,443],
"ftp":[20,21]
}

def serviceID(ip,subs):
    records = []
    
    #verifier les ports par defaults
    for sub in subs:
        s = sub.strip("0123456789")
        if s in defaults:
            records = [bannerRecord(ip,p) for p in defaults[s]]
        
    
    # verifier shodan
    if len(records) == 0:
        records = ShodanLookup(ip)
        for r in records:
            if not "product" in r:
                [r["product"],r["version"]] = parseBanner(r["banner"],r["port"])
    # scanner les ports communs
    if len(records) == 0:
        records = [bannerRecord(ip,p) for p in SynScan(ip)]
        
    return records
    

def bannerRecord(ip, p):
    product = ""
    version = ""
    if p in [80,443,8080,8443]:
        response = HTTPHeaderGrab(ip,p)
        server= response.headers["Server"]
        [product,version] = parseBanner(server,p)
    else:
        banner = bannerGrab(ip,p)
        if banner:
            [product,version] = parseBanner(banner,p)
    r = {
        "port": p,
        "product": product,
        "version": version
        }
        
    return r    




def parseBanner(banner, port):
    product = ""
    version = ""
    if port in [80, 443, 8080, 8443]:
        if banner.startswith("HTTP"):
            match = re.search(r"Server: ([^\r\n]*)", banner)
            if match:
                server = match.group(1)
            else:
                server = banner
            vals = server.split(" ")[0].split("/")
            product = vals[0]
            version = vals[1] if len(vals) > 1 else ""
        else:
            x = re.search(r"([A-Za-z0-9]+)[/ _]([0-9]+(\.[0-9]+)*)", banner)
            if x:
                product = x.group(1)
                version = x.group(2)
            else:
                x = re.findall(r"([a-z0-9]*((smtp)|(ftp))[a-z0-9]*)", banner.lower())
                if x:
                    for y in x:
                        if y[0] != "esmtp":
                            product = y[0]
                            break
    else:
        x = re.search(r"\(([^)]+)\)", banner)
        if x:
            product_info = x.group(1)
            product_and_version = product_info.split(" ")
            if len(product_and_version) >= 2:
                product = product_and_version[0]
                version = product_and_version[1]

    return [product, version]   

def extract_info(data):
    port = data['port']
    product = data['product']
    try :
        version = data['version'] 
    except:
        version = ""
    return {'port': port, 'product': product, 'version': version}    


records = serviceID("84.39.116.122","")
for rec in records:
    print(rec)
result_list = [extract_info(data) for data in records]
print("\n\n")
for item in result_list:
    print(item)

    
            