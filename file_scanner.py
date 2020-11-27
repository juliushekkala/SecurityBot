'''Scans the files using YARA'''
import yara
import json
import os

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
'''
async def scan_file(data):
    #first, load the YARA rules
    rules = load_rules()
    matches = rules.match(data)
    print(matches)
    #If matches within the rules
    if len(matches) > 0:
        return False
    else:
        return True

