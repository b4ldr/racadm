#!/usr/bin/env python
import requests
import logging
import xml.etree.ElementTree as ET

class Racadm(object):

    def __init__(self, hostname='localhost', username='root', password='calvin', port=443, log_level=logging.INFO, verify=False):
        '''initialise variables'''

        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.verify = verify
        logging.basicConfig(level=log_level)
        self.session = requests.Session()
        self.cgiuri = 'https://{}:{}/cgi-bin/'.format(self.hostname, self.port)
        self.login_state = None

    def _get_response(self, uri, payload):
        '''get a payload from uri'''

        logging.debug('>>>>>>>>>>>>>>>>>>>\n{}'.format(payload))
        response = self.session.post(uri, data=payload, verify=self.verify)
        logging.debug('<<<<<<<<<<<<<<<<<<<\n{}'.format(response.content))
        return response.content

    def _search_xml(self, xml_message, element):
        '''search an xml message for a specific element'''

        root_element = ET.fromstring(xml_message)
        return root_element.find('.//{}'.format(element))
    def _parse_login(self, response):
        '''check that login succeeded'''

        sid = self._search_xml(response, 'SID').text
        self.login_state = self._search_xml(response, 'STATENAME').text
        logging.debug('SID:{}, STATE: {}'.format(sid, self.login_state))
        if self.login_state == 'OK':
            cookie = { 'sid': sid }
            self.session.update(cookies=cookie)
            return True
        return False


    def login(self):
        '''Login to the drac server and get a cookie'''
        
        uri = '{}login'.format(self.cgiuri)
        payload = '<?xml version=\'1.0\'?><LOGIN><REQ>'\
                '<USERNAME>{}</USERNAME><PASSWORD>{}</PASSWORD>'\
                '</REQ></LOGIN>'.format(self.username, self.password)
        content = self._get_response(uri, payload)
        return self._parse_login(content)

    def run_command(self, command):
        '''run the racadm command'''

        uri = '{}exec'.format(self.cgiuri)
        payload = '<?xml version=\'1.0\'?><EXEC><REQ>'\
                '<CMDINPUT>{}</CMDINPUT><MAXOUTPUTLEN>0x0fff</MAXOUTPUTLEN>'\
                '</REQ></EXEC>'.format(command)
        content = self._get_response(uri, payload)


def main():
    '''cli component of racadm'''
    racadm.login()
    racadm.run_command('vmdisconnect')

if __name__ == '__main__':
    main()
