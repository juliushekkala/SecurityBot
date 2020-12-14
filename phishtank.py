import requests
import base64
import json
import datetime


class PhishTank():

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

    def _check_url_with_api(self, url, api_key):
        '''
        Checks a given url with phistank api
        :param url: String
        :return: json dict or None
        '''
        api_url = 'https://checkurl.phishtank.com/checkurl/'
        print("checking url", url)
        post_data = {
            'url': base64.b64encode(url.encode("utf-8")),
            'format': 'json',
            'app_key': api_key,
        }
        response = requests.post(self.api_url, data=post_data)
        data = response.json()
        return data

    def get_phistank_db(self, api_key):
        '''
        Gets the latest phishtank database. if unsuccessful tries to use old local db.
        :return: json phishtank database
        '''
        try:
            db_url = 'http://data.phishtank.com/data/%s/online-valid.json' %(api_key)
            print('Fetching phishing database from ', db_url)
            response = requests.get(db_url)
            print(response)
            db = response.json()
            db_status = {"datetime": datetime.datetime.now(), "status": 'OK', "status_code": response.status_code}
        except:
            print('Error occurred while fetching phishing database, try updating the phishtank api key')
            db = "Database Error"
            db_status = {"datetime": datetime.datetime.now(), "status": 'DatabaseError', "status_code": response.status_code}

        return db, db_status

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

    def db_up_to_date(self, db_datetime):
        '''
        Return True(db is up to date) if time since db_datetime is less than 4 hrs(14400 seconds)
        '''
        timedelta = datetime.datetime.now() - db_datetime
        if timedelta.seconds <= 14400:
            return True
        else:
            return False
