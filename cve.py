# -*- coding: utf-8 -*-
import json
import re
import csv
import sys


def filterDriver(description):
    m = re.findall(r'driver', description, re.IGNORECASE)
    if m:
        return True
    return False


def findFuncNames(description):
    functions = []
    patterns = [r'(?:The|the) ([A-Za-z0-9_]+) function[,\.\s]', r'([A-Za-z0-9_]+)\(\)', r'([A-Za-z0-9]+_[A-Za-z0-9_]+) in [A-Za-z0-9_/]+\.[cS]', r'(?:The|the) function ([A-Za-z0-9_]+)', r'(?:The|the) ([A-Za-z0-9_]+) and ([A-Za-z0-9_]+) functions', r'(?:The|the) \(1\) ([A-Za-z0-9_]+) and \(2\) ([A-Za-z0-9_]+) functions']
    for pattern in patterns:
        m = re.findall(pattern, description)
        if m:
            for name in m:
                if isinstance(name ,tuple):
                    for da in name:
                        functions.append(da)
                else:
                    functions.append(name)

    path = []
    m = re.findall(r' [A-Za-z0-9_/]+\.[cS][,\.\s]', description)
    if m:
        for name in m:
            path.append(name)        

    return " ".join(functions), " ".join(path)
    

def numMatch(str1, str2, op):
    if int(str1) < int(str2):
        if op == "<=" or op == "<":
            return True
        else:
            return False
    elif int(str1) > int(str2):
        if op == ">=" or op == ">":
            return True
        else:
            return False
    else:
        if op == "=" or op == "<=" or op == ">=":
            return True
        else:
            return False


debug = False
# debug = True

def cmp(T1, T2):
    P1 = T1[:]
    P2 = T2[:]
    while len(T1) < len(T2):
        T1.append('0')
    while len(T2) < len(T1):
        T2.append('0')
    return T1 == T2

#########################
#########################
# 比较数字+字母大小
def cmpStr(tint, tstr, vint, vstr, equ):
#    print(type(tint))
#    print(type(vint))
    if tint == "" and vint != "":
        return True
    if vint == "" and tint != "":
        return False
    if vint != "" and tint != "":
        if int(str(tint)) < int(str(vint)):
            return True
        if int(str(vint)) < int(str(tint)):
            return False
    if bool(equ):
        return str(tstr) <= str(vstr)
    else:
        return str(tstr) < str(vstr)

# 辅助分割数字和字母 
def getPos(ss):
    for i in range(len(ss)):
        if ss[i] > '9' or ss[i] < '0':
            return i
    return len(ss)

# target : 目标应用版本
# version : json 中的版本
# equ: True 表示version_affected为"="， False 表示version_affected为"<="
# 版本号样例 1.10.1a
def cmpVersion(target, version, equ):
    target = re.split('\W+', target)
    version = re.split('\W+', version)
#    print(target)
#    print(version)
    length = max(len(version), len(target))
    for i in range(length):
        tstr = "0"
        vstr = "0"
        if i < len(target):
            tstr = target[i]
        if i < len(version):
            vstr = version[i]
        # version_affected为"="
        if bool(equ):
            if str(tstr) != str(vstr):
                return False
            continue
        # version_affected为"<="
        tpos = getPos(tstr)
        vpos = getPos(vstr) 
#        print(tpos)
#        print(vpos)
        if not cmpStr(tstr[:tpos], tstr[tpos:], vstr[:vpos], vstr[vpos:], True):
            return False
    return True

#########################
#########################

def versionIsMatch(target, relationship, version, last_version):

#########################
#########################

    if version == "*" or version == "-":
        return False
    if relationship == "=":
        return cmpVersion(target, version, True)
    else:
        return cmpVersion(target, version, False) and not cmpVersion(target, last_version, False)

#########################
#########################
    targetTokens = re.split("\D+", target)
    versionTokens = re.split("\D+", version)
    if version == "*" or version == "-":
        return False
    return cmp(targetTokens, versionTokens)

    if debug:
        print(target)
        print(version)
        print(targetTokens)
        print(versionTokens)
        print(relationship)
    if version == "*" or version == "-":
        return False
    for i in range(len(versionTokens)):
        if i >= len(targetTokens):
            # target的version没了，而cve里的version还有
            return False
        if int(targetTokens[i]) == int(versionTokens[i]):
            continue
        else:
            return numMatch(targetTokens[i], versionTokens[i], relationship)
    # equal
    if relationship == "=" or relationship == "<=" or relationship == ">=":
        return True
    return False


'''
Description: According to the information of targetSoftware (e.g. Linux kernel), we search CVE dataset to find CVE IDs that influence the targetSoftware.
The searching  results are stored in kernel_searching_results
Input: sys.argv[1] (the name of the target software)
        sys.argv[2] (the version of the target software)
Output: ./software-Tmpoutput/name-version, which records the CVE ID
''' 

targetSoftware = { "name":"default", "version":"default",  "ever_found": "false", "count": 0 }

# We obtain the version of target Linux kernel (we need to find all the CVE Item that influences it) from command line
targetSoftware["name"] = sys.argv[1]
targetSoftware["version"] = sys.argv[2]
TmpDir = sys.argv[3]


foutput = "./output.csv"
if len(sys.argv) > 1:
    foutput = TmpDir+"/" + str(sys.argv[1]) + "-" + str(sys.argv[2])

print("scanning for " + str(sys.argv[1]) + "-" + str(sys.argv[2]))
#print("results are saved in" + foutput)

# we open a output.csv file and the search results are written to this file.
#with open("./output.csv", 'w') as csvOutputFile:
with open(foutput, 'w') as csvOutputFile:
    writer = csv.writer(csvOutputFile)
    # We check the nvdcve information from 2013 to 2020
    for year in range(2013, 2020):
        print("scanning year "+str(year))
        # Open the json file that stores the CVE information
        with open('./nvdcve-json/nvdcve-1.1-'+str(year)+'.json', encoding = "utf-8") as f:
            data = json.load(f)
            # Obtain CVE Items which contains information of many CVE ID 
            for cve in data["CVE_Items"]:
                # Obtain the CVE ID
                id = cve["cve"]["CVE_data_meta"]["ID"]
                # Obtain the vendors that the CVE influences
                vendorDatas = cve["cve"]["affects"]["vendor"]["vendor_data"]
                for vdd in vendorDatas:
                    for product in vdd["product"]["product_data"]:               
                        productName = product["product_name"]
                        # If the productName is Linux_kernel
                        if productName.lower() == targetSoftware["name"].lower():
                            # We have found CVE ID that influences Linux Kernel
                            targetSoftware["ever_found"] = "true"
                            last_version = "0"
                            # We tranverse all the influenced versions of the CVE
                            for version in product["version"]["version_data"]:
                                if debug:
                                    print("year:"+str(year)+"  "+product["product_name"]+" "+id)
                                # if targetSoftware["version"] is a affected version
#######################
#######################
#                                if version["version_value"] == "4.18.1":
#                                    print("###########################")
#                                    print(id)
#                                    print(versionIsMatch(targetSoftware["version"], version["version_affected"], version["version_value"], last_version))
#                                    print("###########################")
                                        
#######################
#######################
                                if versionIsMatch(targetSoftware["version"], version["version_affected"], version["version_value"], last_version):
                                    last_version = version["version_value"]
                                    cweType = cve["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
                                    vversion = "3"
                                    if not vversion in cve["impact"]:
                                        vversion = "2"
                                    baseScore = cve["impact"]["baseMetricV"+vversion]["cvssV"+vversion]["baseScore"]
                                    # impactScore = cve["impact"]["baseMetricV"+vversion]["impactScore"]
                                    vector = cve["impact"]["baseMetricV"+vversion]["cvssV"+vversion]["vectorString"]
                                    description = cve["cve"]["description"]["description_data"][0]["value"]
                                    refs = cve["cve"]["references"]["reference_data"]
                                    patchUrls = ""
                                    for j in range(len(refs)):
                                        ref = refs[j]
                                        patchReference = False
                                        tags = ref["tags"]
                                        for k in range(len(tags)):
                                            if tags[k] == "Patch":
                                                patchReference = True
                                                break
                                        if patchReference:
                                            patchUrls = patchUrls + "\n" + ref["url"]
                                    # Obtain the influenced function name and the path of this function
                                    funcStr, funcPath = findFuncNames(description)
                                    if filterDriver(description):
                                        continue
                                    targetSoftware["count"] += 1
                                    writer.writerow([id])
                                last_version = version["version_value"] 


if not targetSoftware["ever_found"]:
    print(targetSoftware["name"]+"  has not ever been found")
else:
    print("For "+targetSoftware["name"] + " : " + targetSoftware["version"] + ", we have found " + str(targetSoftware["count"])+" related CVE ID.")

