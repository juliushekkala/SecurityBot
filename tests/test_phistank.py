import unittest
from phishtank import PhishTank
db = PhishTank._open_local_db('test_db.json')

class TestUrlChecking(unittest.TestCase):
    def test_check_urls(self):
        #self.assertEqual(PhishTank().check_urls(['https://eefailedpayments.co.uk/'], db), [{'phish_id': '6866630', 'url': 'https://eefailedpayments.co.uk/', 'phish_detail_url': 'http://www.phishtank.com/phish_detail.php?phish_id=6866630', 'submission_time': '2020-11-28T10:33:23+00:00', 'verified': 'yes', 'verification_time': '2020-11-28T10:34:17+00:00', 'online': 'yes', 'details': [{'ip_address': '162.0.209.176', 'cidr_block': '162.0.208.0/20', 'announcing_network': '22612', 'rir': 'arin', 'country': 'US', 'detail_time': '2020-11-28T10:34:35+00:00'}], 'target': 'Other'}])
        self.assertEqual(PhishTank().check_urls(['https://notindatabse.com'], db), [None])
        self.assertEqual(PhishTank().check_urls(['https://eefailedpayments.co.uk/', 'https://notindatabse.com', 'https://notindatabse.com'], db), [{'phish_id': '6866630', 'url': 'https://eefailedpayments.co.uk/', 'phish_detail_url': 'http://www.phishtank.com/phish_detail.php?phish_id=6866630', 'submission_time': '2020-11-28T10:33:23+00:00', 'verified': 'yes', 'verification_time': '2020-11-28T10:34:17+00:00', 'online': 'yes', 'details': [{'ip_address': '162.0.209.176', 'cidr_block': '162.0.208.0/20', 'announcing_network': '22612', 'rir': 'arin', 'country': 'US', 'detail_time': '2020-11-28T10:34:35+00:00'}], 'target': 'Other'}, None, None])

    def test_check_url(self):
        self.assertEqual(PhishTank()._check_url('https://eefailedpayments.co.uk/',db), {'phish_id': '6866630', 'url': 'https://eefailedpayments.co.uk/', 'phish_detail_url': 'http://www.phishtank.com/phish_detail.php?phish_id=6866630', 'submission_time': '2020-11-28T10:33:23+00:00', 'verified': 'yes', 'verification_time': '2020-11-28T10:34:17+00:00', 'online': 'yes', 'details': [{'ip_address': '162.0.209.176', 'cidr_block': '162.0.208.0/20', 'announcing_network': '22612', 'rir': 'arin', 'country': 'US', 'detail_time': '2020-11-28T10:34:35+00:00'}], 'target': 'Other'})
        self.assertEqual(PhishTank()._check_url('https://eefailedpayments.asd/', db), None)

if __name__ == '__main__':
    unittest.main()
