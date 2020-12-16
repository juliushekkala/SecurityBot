# File for utility functions

import re
import configparser
import os

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
        config.read('config.ini', encoding='utf-8')
        #TODO: Validity check for config
        try:
            if config.getboolean("BOTREACT", "msgokreact"):
                config.get("BOTREACT", "msgokreacttype")
            config.getboolean("BOTREACT", "msgokanswer")
            config.getboolean("SCAN", "scanfile")
            config.getboolean("SCAN", "scanlink")
            config.getboolean("SCAN", "pdfscan")
            config.getboolean("SCAN", "autoscan")
            return config
        except:
            print("Config could be faulty. Creating a new one")
            os.remove('config.ini')
            return createBotConfig()

    except FileNotFoundError:
        #Create new config file
        return createBotConfig()

# Function for creating the default config
# Used if config not present
# Returns new ConfigParser
def createBotConfig():
    config = configparser.ConfigParser()
    config['BOTREACT'] = {'MsgOKReact': '1',
                        'MsgOKReactType': '\N{THUMBS UP SIGN}',
                        'MsgOKAnswer': '0'}
    config['SCAN'] = {'Autoscan': '1',
                    'ScanFile': '1',
                    'ScanLink': '1',
                    'PdfScan': '0'}
    with open('config.ini', 'w', encoding='utf-8') as configfile:
        config.write(configfile)
    return config