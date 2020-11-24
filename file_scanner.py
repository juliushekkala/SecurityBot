'''Scans the files using YARA'''
import yara
import json

#Filepaths to the YARA files
with open('yara_files.json') as f:
    filepaths = json.load(f)
    f.close()

rules = yara.compile(filepaths=filepaths)

#testing
matches = rules.match('../testi.txt')
print(matches)