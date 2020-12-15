# File for utility functions

import re
import configparser

# The function finds URLs in given strings
# Args: string inputString - the string with possible URLs
# Returns list of URLs (string)
def findURLs(inputString):
    web_url_regex = r"(https?://[^\s]+)" # Crude and not accurate in all cases. Discord itself seems to show preview with a similar crude logic.
    urls = re.findall(web_url_regex, inputString)
    print(urls)
    return urls

# Read config and create new one if does not exist
# Returns ConfigParser
def getConfig():
    try:
        f = open('config.ini')
        f.close()
        config = configparser.ConfigParser()
        config.read('config.ini')
        #TODO: Validity check for config
        return config
    except FileNotFoundError:
        #Create new config file
        return createBotConfig()

# Function for creating the default config
# Used if config not present
# Returns new ConfigParser
def createBotConfig():
    config = configparser.ConfigParser()
    config['BOTREACT'] = {'MsgOKReact': '1',
                        'MsgOKReactType': 'U+1F44D',
                        'MsgOKAnswer': '0'}
    config['SCAN'] = {'Autoscan': '1',
                    'ScanFile': '1',
                    'ScanLink': '1',
                    'PdfScan': '0'}
    with open('config.ini', 'w') as configfile:
        config.write(configfile)
    return config