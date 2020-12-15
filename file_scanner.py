'''Scans the files using YARA'''
import yara
import json
import os
import subprocess

'''Load YARA rules from a JSON file
containing the YARA rule file locations'''
def load_rules_from_json():
    with open('yara_files.json') as f:
        #Filepaths to the YARA files
        filepaths = json.load(f)
        f.close()
        rules = yara.compile(filepaths=filepaths)
        return rules

'''Load YARA rules'''
def load_rules():
    #If the rules have been compiled before
    if os.path.exists('yara_compiled_rules'):
        rules = yara.load('yara_compiled_rules')
    #First time compiling the rules
    else:
        rules = load_rules_from_json()
        rules.save('yara_compiled_rules')
    return rules

'''Scan a file
Returns true, if no matches found
Returns false, if at least one match

If the file extension is pdf and using yextend to scan PDF files is enabled
in the config, use yextend 
to scan the file as a proof-of-concept.
'''
async def scan_file(data, config):
    
    #first, load the YARA rules
    rules = load_rules()
    filename, file_extension = os.path.splitext(data)
    print("File extension is " + str(file_extension))
    #If the file extension is pdf and scanning pdf with yextend is enabled in the config
    if file_extension == ".pdf" and config.getboolean("SCAN", "pdfscan"):
        #Yara rules need to be in a folder called yara_rules
        output = subprocess.check_output(["./yextend", "-r", "yara_rules/*", "-t", data, "-j"])
        str_output = output.decode('utf-8')
        cleaned_output = str_output.strip().replace("\n","")
        cleaned_output = cleaned_output.replace("\\","")
        json_output = json.loads(cleaned_output)
        print(json_output)
        try: 
            if json_output[0]["yara_matches_found"] == True:
                return False
            else:
                return True  
        except KeyError:
            return True  	
    matches = rules.match(data)
    print(matches)
    #If matches within the rules
    if len(matches) > 0:
        return False
    else:
        return True

