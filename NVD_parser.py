import requests
import urllib3
import json
import datetime

import getopt, sys

class NVDAPI:
    def __init__(self):
        self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.API = "6b07a4ac-1c45-4890-bcc7-9a5aeee8137c"
        #API Key: 6b07a4ac-1c45-4890-bcc7-9a5aeee8137c
        self.headers = {
                "apiKey" : self.API
            }
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("[+] NVD API Initialized")
        self.error = 0
        log = "logs\\" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".log"
        self.log = open(log, "w")
        self.silent = 0
        self.output = "output.json"
        self.initial = "initial.json"
    
    def get_cve(self, cve_id):
        #self.print("[+] Getting CVE: ", cve_id, " from NVD: ", self.url)
        url = self.url
        response = requests.get(url, params={'cveId': cve_id}, headers=self.headers, verify=False)
        status = response.status_code
        if status != 200:
            if self.error == 0:
                self.print("[!] Error: " + str(status))
                self.error = status
            else:
                self.print(".", end="")
            return status
        self.error = 0
        self.print("\n[+] Got CVE: ", cve_id)
        try:
            return response.json()
        except:
            return response
    
    def get_resp(self, keys, args):
        url = self.url
        param = {}
        for key,arg in keys,args:
            param[key] = arg
        response = requests.get(url, params={keys: args}, headers=self.headers, verify=False)
        status = response.status_code
        if status != 200:
            if self.error == 0:
                self.print("[!] Error: " + str(status))
                self.error = status
            else:
                self.print(".", end="")
            return status
        self.error = 0
        self.print("\n[+] Got '", arg, "' from NVD")
        try:
            return response.json()
        except:
            return response
    
    def get_by_cpe(self, cpe, page=0):
        url = self.url
        param = {"resultsPerPage": "2000", "startIndex": str(page * 2000), "cpeName": cpe}
        url = url + "/?" + "resultsPerPage=2000&startIndex=" + str(page * 2000) + "&cpeName=" + cpe
        response = requests.get(url, headers=self.headers, verify=False)
        status = response.status_code
        if status != 200:
            self.print("[!] Error: " + str(status))
            return status
        self.error = 0
        self.print("\n[+] Got '", cpe, "' from NVD")
        try:
            return response.json()
        except:
            return response
    
    def get_cve_by_date(self, days):
        date = datetime.datetime.now()
        moddate = date - datetime.timedelta(days=days)
        str_date = date.strftime("%Y-%m-%dT%X") + ".000%2B05:30"
        str_datedays = moddate.strftime("%Y-%m-%dT%X") + ".000%2B05:30"
        #self.print("[+] Getting CVEs from NVD: ", self.url, " for dates: ", str_date, " and ", str_datedays)
        #params={'lastModStartDate': str_datedays.strip(), 'lastModEndDate': str_date.strip()}
        url = self.url.strip() + "/?pubStartDate=" + str_datedays.strip() + "&pubEndDate=" + str_date.strip()
        #self.print(url)
        #url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00"
        response = requests.get(url, headers=self.headers, verify=False)
        status = response.status_code
        if status != 200:
            self.print("[!] Error: " + str(status))
            return status
        self.print("\n[+] Got CVEs for dates: ", str_datedays, " and ", str_date)
        try:
            return response.json()
        except:
            return response
    
    def actual_json(self):
        template = {
            "CVE_Items": [
                {
                    "cve": {
                        "data_type": "CVE",
                        "data_format": "MITRE",
                        "data_version": "4.0",
                        "CVE_data_meta": {
                            "ID": "CVE-2023-0002",
                            "ASSIGNER": "psirt@paloaltonetworks.com"
                        },
                        "problemtype": {
                            "problemtype_data": [
                                {
                                    "description": [
                                        {
                                            "lang": "en",
                                            "value": "NVD-CWE-Other"
                                        }
                                    ]
                                }
                            ]
                        },
                        "references": {
                            "reference_data": [
                                {
                                    "url": "https://security.paloaltonetworks.com/CVE-2023-0002",
                                    "name": "https://security.paloaltonetworks.com/CVE-2023-0002",
                                    "refsource": "MISC",
                                    "tags": [
                                        "Vendor Advisory"
                                    ]
                                }
                            ]
                        },
                        "description": {
                            "description_data": [
                                {
                                    "lang": "en",
                                    "value": "A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local user to execute privileged cytool commands that disable or uninstall the agent.\n"
                                }
                            ]
                        }
                    },
                    "configurations": {
                        "CVE_data_version": "4.0",
                        "nodes": [
                            {
                                "operator": "AND",
                                "children": [
                                    {
                                        "operator": "OR",
                                        "children": [],
                                        "cpe_match": [
                                            {
                                                "vulnerable": True,
                                                "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "5.0",
                                                "versionEndExcluding": "5.0.12.22203",
                                                "cpe_name": []
                                            },
                                            {
                                                "vulnerable": True,
                                                "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:critical_environment:*:*:*",
                                                "versionStartIncluding": "7.5",
                                                "versionEndIncluding": "7.5.101",
                                                "cpe_name": []
                                            }
                                        ]
                                    },
                                    {
                                        "operator": "OR",
                                        "children": [],
                                        "cpe_match": [
                                            {
                                                "vulnerable": False,
                                                "cpe23Uri": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                                                "cpe_name": []
                                            }
                                        ]
                                    }
                                ],
                                "cpe_match": []
                            }
                        ]
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "LOCAL",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 7.8,
                                "baseSeverity": "HIGH"
                            },
                            "exploitabilityScore": 1.8,
                            "impactScore": 5.9
                        }
                    },
                    "publishedDate": "2023-02-08T18:15Z",
                    "lastModifiedDate": "2023-11-07T03:59Z"
                }
            ]
        }
    
    def recieved(self):
        generated = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0002",
                        "sourceIdentifier": "psirt@paloaltonetworks.com",
                        "published": "2023-02-08T18:15:11.683",
                        "lastModified": "2023-11-07T03:59:26.433",
                        "vulnStatus": "Modified",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local user to execute privileged cytool commands that disable or uninstall the agent.\n"
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                        "attackVector": "LOCAL",
                                        "attackComplexity": "LOW",
                                        "privilegesRequired": "LOW",
                                        "userInteraction": "NONE",
                                        "scope": "UNCHANGED",
                                        "confidentialityImpact": "HIGH",
                                        "integrityImpact": "HIGH",
                                        "availabilityImpact": "HIGH",
                                        "baseScore": 7.8,
                                        "baseSeverity": "HIGH"
                                    },
                                    "exploitabilityScore": 1.8,
                                    "impactScore": 5.9
                                },
                                {
                                    "source": "psirt@paloaltonetworks.com",
                                    "type": "Secondary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                                        "attackVector": "LOCAL",
                                        "attackComplexity": "LOW",
                                        "privilegesRequired": "LOW",
                                        "userInteraction": "NONE",
                                        "scope": "UNCHANGED",
                                        "confidentialityImpact": "NONE",
                                        "integrityImpact": "NONE",
                                        "availabilityImpact": "HIGH",
                                        "baseScore": 5.5,
                                        "baseSeverity": "MEDIUM"
                                    },
                                    "exploitabilityScore": 1.8,
                                    "impactScore": 3.6
                                }
                            ]
                        },
                        "weaknesses": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "description": [
                                    {
                                        "lang": "en",
                                        "value": "NVD-CWE-Other"
                                    }
                                ]
                            },
                            {
                                "source": "psirt@paloaltonetworks.com",
                                "type": "Secondary",
                                "description": [
                                    {
                                        "lang": "en",
                                        "value": "CWE-693"
                                    }
                                ]
                            }
                        ],
                        "configurations": [
                            {
                                "operator": "AND",
                                "nodes": [
                                    {
                                        "operator": "OR",
                                        "negate": False,
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "5.0",
                                                "versionEndExcluding": "5.0.12.22203",
                                                "matchCriteriaId": "213B017D-D17C-460A-BC5C-6B6A4BFFA8E4"
                                            },
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:critical_environment:*:*:*",
                                                "versionStartIncluding": "7.5",
                                                "versionEndIncluding": "7.5.101",
                                                "matchCriteriaId": "C72CD204-E989-4990-A4AF-BFE65817CD31"
                                            }
                                        ]
                                    },
                                    {
                                        "operator": "OR",
                                        "negate": False,
                                        "cpeMatch": [
                                            {
                                                "vulnerable": False,
                                                "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                                                "matchCriteriaId": "A2572D17-1DE6-457B-99CC-64AFD54487EA"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "references": [
                            {
                                "url": "https://security.paloaltonetworks.com/CVE-2023-0002",
                                "source": "psirt@paloaltonetworks.com",
                                "tags": ["Vendor Advisory"]
                            }
                        ]
                    }
                }
            ]
        }
        return generated
    
    def do_logic(self, configurations):
        nodes = []
        #if "operator" not in configurations[0]:
            #return self.do_logic(configurations[0]["nodes"])
        for node in configurations:
            if "operator" not in node:
                nodes.append(self.do_logic(node["nodes"])[0])
                continue
            operator = node["operator"]
            children = None
            cpe_match = None
            if "negate" in node and node["negate"] == False:
                children = []
                cpe_match = node["cpeMatch"]
                full = {
                    "operator": operator,
                    "children": children,
                    "cpe_match": self.cpe_matching(cpe_match)
                }
            else:
                children = self.do_logic(node["nodes"])
                full = {
                    "operator": operator,
                    "children": children,
                    "cpe_match": []
                }
            nodes.append(full)
        return nodes
    
    def cpe_matching(self, cpe_match):
        cpe = []
        for match in cpe_match:
            match["cpe23Uri"] = match["criteria"]
            match["cpe_name"] = []
            del match["criteria"]
            cpe.append(match)
        return cpe
    
    def make_json_old(self, response):
        self.print("[+] Making JSON")
        id = response["vulnerabilities"][0]["cve"]["id"]
        assigner = response["vulnerabilities"][0]["cve"]["sourceIdentifier"]
        published = response["vulnerabilities"][0]["cve"]["published"]
        last_modified = response["vulnerabilities"][0]["cve"]["lastModified"]
        description = response["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
        try:
            configurations = response["vulnerabilities"][0]["cve"]["configurations"]
        except:
            print("[!] Error with : ", response["vulnerabilities"][0]["cve"]["id"], " -> (Configurations Parsing)")
            configurations = []
        nodes = self.do_logic(configurations)
        impact = response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]
        references = response["vulnerabilities"][0]["cve"]["references"]
        exploitabilityScore = response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"]
        impactScore = response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"]
        final = {
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {
                            "ID": id,
                            "ASSIGNER": assigner
                        },
                        "references": {
                            "reference_data": references
                        },
                        "description": {
                            "description_data": [
                                {
                                    "lang": "en",
                                    "value": description
                                }
                            ]
                        }
                    },
                    "configurations": {
                        "nodes": nodes
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": impact,
                            "exploitabilityScore": exploitabilityScore,
                            "impactScore": impactScore
                        }
                    },
                    "publishedDate": published,
                    "lastModifiedDate": last_modified
                }
            ]
        }
        return final
    
    def make_json(self, responses):
        self.print("[+] Making JSON")
        items = []
        for response in responses["vulnerabilities"]:
            try:
                id = response["cve"]["id"]
                assigner = response["cve"]["sourceIdentifier"]
                published = response["cve"]["published"]
                last_modified = response["cve"]["lastModified"]
                description = response["cve"]["descriptions"][0]["value"]
                configurations = []
                nodes = []
                try:
                    configurations = response["cve"]["configurations"]
                    nodes = self.do_logic(configurations)
                except:
                    print("[!] Error with : ", response["cve"]["id"], " -> (Configurations)")
                references = response["cve"]["references"]
                impact = []
                exploitabilityScore = []
                impactScore = []
                metric =  "baseMetricV3"
                cvss = "cvssV3"
                try:
                    if "cvssMetricV31" in response["cve"]["metrics"]:
                        impact = response["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]
                        exploitabilityScore = response["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"]
                        impactScore = response["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"]
                    elif "cvssMetricV30" in response["cve"]["metrics"]:
                        impact = response["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]
                        exploitabilityScore = response["cve"]["metrics"]["cvssMetricV30"][0]["exploitabilityScore"]
                        impactScore = response["cve"]["metrics"]["cvssMetricV30"][0]["impactScore"]
                    elif "cvssMetricV2" in response["cve"]["metrics"]:
                        impact = response["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]
                        exploitabilityScore = response["cve"]["metrics"]["cvssMetricV2"][0]["exploitabilityScore"]
                        impactScore = response["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"]
                        metric = "baseMetricV2"
                        cvss = "cvssV2"
                except:
                    print("[!] Error with : ", response["cve"]["id"], " -> (Impact)")
                final = {
                    "cve": {
                        "CVE_data_meta": {
                            "ID": id,
                            "ASSIGNER": assigner
                        },
                        "references": {
                            "reference_data": references
                        },
                        "description": {
                            "description_data": [
                                {
                                    "lang": "en",
                                    "value": description
                                }
                            ]
                        }
                    },
                    "configurations": {
                        "nodes": nodes
                    },
                    "impact": {
                        metric: {
                            cvss: impact,
                            "exploitabilityScore": exploitabilityScore,
                            "impactScore": impactScore
                        }
                    },
                    "publishedDate": published,
                    "lastModifiedDate": last_modified
                }
                items.append(final)
            except Exception as e:
                self.print("[!] Error with : ", response["cve"]["id"])
                self.print(e, log_only=True)
                continue
        full = {
            "CVE_Items": items
        }
        return full
    
    def print(self, *arg, log_only=False, end="\n"):
        line = ""
        cline = ""
        for a in arg:
            line += str(a)
            if "" in str(a):
                while True:
                    try:
                        index = str(a).index("")
                        cline += str(a)[:index]
                        a = str(a)[index+5:]
                    except:
                        break
            cline += str(a)
        if not self.silent >= 2 and not log_only: print(line, end=end)
        self.log.writelines(cline + end)

def by_date(days):
    nvda = NVDAPI()
    resp = "Not null"
    nvda.print("[+] Getting CVEs from NVD for last ", days, " days")
    while type(resp) != dict:
        resp = nvda.get_cve_by_date(days)
    with open(nvda.initial, "w") as f:
        json.dump(resp, f, indent=4, ensure_ascii = True)
    nvda.print(resp, log_only=True)
    nvda.print("[+] Initial JSON Dumped")
    final = nvda.make_json(resp)
    with open(nvda.output, "w") as f:
        json.dump(final, f, indent=4, ensure_ascii = True)
    nvda.print(final, log_only=True)
    nvda.print("[+] Final JSON Dumped")
    return final

def by_cve(cve_id):
    nvda = NVDAPI()
    resp = "Not null"
    nvda.print("[+] Getting CVE: ", cve_id, " from NVD")
    while type(resp) != dict:
        resp = nvda.get_cve(cve_id)
    with open(nvda.initial, "w") as f:
        json.dump(resp, f, indent=4, ensure_ascii = True)
    nvda.print(resp, log_only=True)
    nvda.print("[+] Initial JSON Dumped")
    final = nvda.make_json(resp)
    with open(nvda.output, "w") as f:
        json.dump(final, f, indent=4, ensure_ascii = True)
    nvda.print(final, log_only=True)
    nvda.print("[+] Final JSON Dumped")
    return final
    
def by_cves(file_loc):
    nvda = NVDAPI()
    resp = "Not null"
    resps = []
    full = []
    cves = open(file_loc, "r").readlines()
    for cve_id in cves:
        resp = "Not null"
        nvda.print("[+] Getting CVE: ", cve_id.strip(), " from NVD")
        while type(resp) != dict:
            resp = nvda.get_cve(cve_id.strip())
        resps.append(resp)
        final = nvda.make_json(resp)
        full.append(final["CVE_Items"][0])
    final = {"CVE_Items": full}
    nvda.print(resps, log_only=True)
    with open(nvda.initial, "w") as f:
        json.dump(resps, f, indent=4, ensure_ascii = True)
    nvda.print("[+] Initial JSON Dumped")
    with open(nvda.output, "w") as f:
        json.dump(final, f, indent=4, ensure_ascii = True)
    nvda.print(final, log_only=True)
    nvda.print("[+] Final JSON Dumped")
    return final

def by_cpe(cpe):
    nvda = NVDAPI()
    resp = {}
    nvda.print("[+] Getting CVEs from NVD for CPE: ", cpe)
    page = 0
    full = {}
    while True:
        resp = nvda.get_by_cpe(cpe, page)
        if type(resp) != dict:
            continue
        if page == 0:
            full = resp
        else:
            full["vulnerabilities"] += resp["vulnerabilities"]
        if int(resp["totalResults"]) > (int(resp["startIndex"]) + 2000):
            nvda.print("[+] Got page ", page, " of ", int(resp["totalResults"]) // 2000, " pages")
            page += 1
        else:
            break
    resp = full
    nvda.print(resp, log_only=True)
    with open(nvda.initial, "w") as f:
        json.dump(resp, f, indent=4, ensure_ascii = True)
    nvda.print("[+] Initial JSON Dumped")
    final = nvda.make_json(resp)
    with open(nvda.output, "w") as f:
        json.dump(final, f, indent=4, ensure_ascii = True)
    nvda.print(final, log_only=True)
    nvda.print("[+] Final JSON Dumped")
    return final

if __name__ == "__main__":
    argList = sys.argv[1:]
    options = "d:c:f:p:"
    loptions = ["days=", "cve=", "file=", "cpe="]
    try:
        arguments, values = getopt.getopt(argList, options, loptions)
        for currentArgument, currentValue in arguments:
            if currentArgument in ("-d", "--days"):
                by_date(int(currentValue))
            elif currentArgument in ("-c", "--cve"):
                by_cve(currentValue)
            elif currentArgument in ("-f", "--file"):
                by_cves(currentValue)
            elif currentArgument in ("-p", "--cpe"):
                by_cpe(currentValue)
    except getopt.error as err:
        print(str(err))
        sys.exit(2)