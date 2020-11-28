import requests
import base64
import json


class PhishTank():
    _api_url = 'https://checkurl.phishtank.com/checkurl/'
    _api_key = '71eb7630c802246337a611a556cf1c4ac869df74ab24c94471766f887970d878'

    def check_urls(self, urls, db):
        '''
        Checks a list of urls against a phishing database
        :param urls: list of url strings
        :param db: json phishing database
        :return: list of dictionaries
        '''
        urls_phish_data = []
        for url in urls:
            response = self._check_url(url, db)
            urls_phish_data.append(response)
            '''try:
                response = self._check_url(self, url, db)
                urls_phish_data.append(response)
            except:
                print('Error when checking url ', url)
                pass'''
        return urls_phish_data

    def _check_url_with_api(self, url):
        '''
        Checks a given url with phistank api
        :param url: String
        :return: json dict or None
        '''
        print("checking url", url)
        post_data = {
            'url': base64.b64encode(url.encode("utf-8")),
            'format': 'json',
            'app_key': self._api_key,
        }
        response = requests.post(self._api_url, data=post_data)
        data = response.json()
        return data

    def get_phistank_db(self):
        '''
        Tries to get the latest phishtank database. If unsuccessfull opens local backup.
        :return: json phishtank database
        '''
        try:
            db_url = 'http://data.phishtank.com/data/%s/online-valid.json' %(self._api_key)
            print('Fetching phishing database from ', db_url)
            response = requests.get(db_url)
            print(response)
            db = response.json()
        except:
            print('Error occurred while fetching phishing database, using local backup.')
            db = self._open_local_db('db.json')
        return db

    @staticmethod
    def _open_local_db(path):
        '''
        :param path: path to json file
        :return: opened json file
        '''
        with open(path) as json_file:
            db = json.load(json_file)
            return db

    def _check_url(self, url, db):
        '''
        A very simple checker for a url in the given phishing database
        :param url: url to be checked
        :param db: database of known urls(list of dictionaries)
        :return: matching dictionary or None
        '''
        for entry in db:
            if url == entry['url']:
                return entry
        return None

    def parse_response(self, urls_info):
        message = ''
        for info in urls_info:
            if info is not None:
                message = message + 'The url %s directs users to a verified phishing site. \nFind out more at %s. \n\n' % (info['url'], info['phish_detail_url'])
        if message == '':
            return None
        else:
            return message
