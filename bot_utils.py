# File for utility functions

import re

# The function finds URLs in given strings
# Args: string inputString - the string with possible URLs
# Returns list of URLs (string)
def findURLs(inputString):
    web_url_regex = r"(https?://[^\s]+)" # Crude and not accurate in all cases. Discord itself seems to show preview with a similar crude logic.
    urls = re.findall(web_url_regex, inputString)
    print(urls)
    return urls

