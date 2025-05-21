import os
import getopt, sys
import json

from NVD_parser import NVDAPI

NVD = NVDAPI()

updateFile = None
outputFile = "updatedJson.json"

def update_impact_json(updateFile, outputFile, cveId=""):
    if not os.path.exists(updateFile):
        print(f"Update file {updateFile} does not exist.")
        return
    try:
        with open(updateFile, 'r', encoding="utf-8") as f:
            updateJson = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {updateFile}: {e}")
        return
    newCVEJson = []
    for CVE in updateJson["CVE_Items"]:
        print("\n\nProcessing CVE: ", CVE["cve"]["CVE_data_meta"]["ID"])
        if CVE["impact"] == {}:
            print("No impact data found for CVE: ", CVE["cve"]["CVE_data_meta"]["ID"])
            try:
                formattedJson = NVD.make_json_old(NVD.get_cve(CVE["cve"]["CVE_data_meta"]["ID"]))
                print("Impact data from NVD API: ", formattedJson["CVE_Items"][0]["impact"])
                CVE["impact"] = formattedJson["CVE_Items"][0]["impact"]
                newCVEJson.append(CVE)
            except Exception as e:
                print(f"Error fetching impact data for CVE {CVE['cve']['CVE_data_meta']['ID']}: {e}")
        else:
            print("Impact data found for CVE: ", CVE["cve"]["CVE_data_meta"]["ID"], "\t--- Skipping")
            newCVEJson.append(CVE)
    try:
        updateJson["CVE_Items"] = newCVEJson
        with open(outputFile, 'w', encoding="utf-8") as f:
            json.dump({"CVE_Items": updateJson}, f, indent=4)
        print(f"Updated JSON written to {outputFile}")
    except Exception as e:
        print(f"Error writing to output file {outputFile}: {e}")

if __name__ == "__main__":
    try:
        argList = sys.argv[1:]
        options = "u:o:c:"
        loptions = ["update=", "output=", "cve="]
        try:
            arguments, values = getopt.getopt(argList, options, loptions)
            cveId = ""
            for currentArgument, currentValue in arguments:
                if currentArgument in ("-u", "--update"):
                    updateFile = currentValue
                elif currentArgument in ("-o", "--output"):
                    outputFile = currentValue
                elif currentArgument in ("-c", "--cve"):
                    cveId = currentValue
                    print("CVE ID: ", cveId)
            print("Update file: ", updateFile)
            print("Output file: ", outputFile)
            update_impact_json(updateFile, outputFile, cveId=cveId)
        except getopt.error as err:
            # output error, and return with an error code
            print(str(err))
            sys.exit(2)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)