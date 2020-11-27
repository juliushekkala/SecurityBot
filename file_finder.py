import os
import sys
import json
'''Utility function that iterates through YARA files from
a specified root directory and creates a JSON file for 
YARA
usage: 'python file_finder.py rootdirectory'
'''



#Iterates through all directories starting from
#a root directory given by the user as a command 
#line argument
def yara_file_finder():
  
    if len(sys.argv) < 2:
        print("Root directory was not specified")
        return
    rootdir = sys.argv[1]

    #Dictionary of all yara files
    yara_files = {}

    #Adapted from the answer here: https://stackoverflow.com/a/19587581 
    for subdir, dirs, files in os.walk(rootdir):
        for file in files:
            if file.endswith(".yara"):
                yara_files[file[:-5]] = os.path.join(subdir, file)
                
    
    yara_files_json = json.dumps(yara_files)
  
    #Create a json file from the dictionary
    with open("yara_files.json", "w") as f:
        f.write(yara_files_json)
        f.close()





if __name__ == "__main__":
    yara_file_finder()