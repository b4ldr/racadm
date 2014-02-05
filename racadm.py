#!/usr/bin/env python
import requests
import logging
import re
import datetime
import xml.etree.ElementTree as ET

class RacStatus(object):
    '''Rac Status codes'''

    RAC_STATUS_SUCCESS = 0x0
    RAC_STATUS_FAILED = 0x1
    RAC_STATUS_INVALID_PARAMETER = 0x2
    RAC_STATUS_BUFFER_TOO_SMALL = 0x3
    RAC_STATUS_FW_OPERATION_FAILED = 0x4
    RAC_STATUS_NOT_FOUND = 0x5
    RAC_STATUS_ALREADY_EXISTS = 0x6
    RAC_STATUS_NOT_ALLOWED = 0x7
    RAC_STATUS_REQUIRED_PARAMETER_MISSING = 0x8
    RAC_STATUS_INPUT_PARAM_TOO_BIG = 0x9
    RAC_STATUS_INPUT_BUFFER_TOO_SMALL = 0x10
    RAC_STATUS_SYS_OPERATION_FAILED = 0x11
    RAC_STATUS_MEM_ALLOC_FAILED = 0x12
    RAC_STATUS_TIME_FUNC_FAILED = 0x13
    RAC_STATUS_DATA_CONVERSION_FAILED = 0x14
    RAC_STATUS_UNSUPPORTED_CFG = 0x15
    RAC_STATUS_INVALID_FILE = 0x16
    RAC_STATUS_FILE_OPEN_FAILED = 0x17
    RAC_STATUS_FILE_READ_FAILED = 0x18
    RAC_STATUS_FILE_WRITE_FAILED = 0x19
    RAC_STATUS_RAC_NOT_PRESENT = 0x20
    RAC_STATUS_RAC_NOT_READY = 0x21
    RAC_STATUS_IPMI_NOT_READY = 0x22
    RAC_STATUS_LOAD_LIB_FAILED = 0x23
    RAC_STATUS_BUSY = 0x24

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

        logging.debug('>{}'.format(payload))
        response = self.session.post(uri, data=payload, verify=self.verify)
        logging.debug('<{}'.format(response.content))
        return response.content

    def _search_xml(self, xml_message, element):
        '''search an xml message for a specific element'''

        root_element = ET.fromstring(xml_message)
        return root_element.find('.//{}'.format(element)).text

    def _parse_login(self, response):
        '''check that login succeeded'''

        sid = self._search_xml(response, 'SID')
        self.login_state = self._search_xml(response, 'STATENAME')
        logging.debug('SID:{}, STATE: {}'.format(sid, self.login_state))
        if self.login_state == 'OK':
            logging.info('Login Successful')
            cookie = { 'sid': sid }
            self.session.cookies.update(cookie)
            return True
        logging.warn('Login Failed')
        return False

    def login(self):
        '''Login to the drac server and get a cookie'''
        
        uri = '{}login'.format(self.cgiuri)
        payload = '<?xml version=\'1.0\'?><LOGIN><REQ>'\
                '<USERNAME>{}</USERNAME><PASSWORD>{}</PASSWORD>'\
                '</REQ></LOGIN>'.format(self.username, self.password)
        content = self._get_response(uri, payload)
        return self._parse_login(content)

    def _parse_command(self, response, command):
        '''check that command succeeded'''

        command_status = int(self._search_xml(response, 'CMDRC').split('x')[1])
        command_output = self._search_xml(response, 'CMDOUTPUT')
        logging.debug('STATUS: {}, OUTPUT: {}'.format(command_status, command_output))
        if command_status == RacStatus.RAC_STATUS_SUCCESS:
            logging.info('racadm {} Successful'.format(command))
        elif command_status == RacStatus.RAC_STATUS_FAILED:
            logging.warn('racadm {} failed: {}'.format(command, command_output))
        elif command_status == RacStatus.RAC_STATUS_INVALID_PARAMETER:
            logging.warn('racadm {} invalid command: {}'.format(command, command_output))
        else:
            logging.warn('racadm {} failed with status {}: {}'.format(command, command_status, 
                command_output))
        return command_status, command_output.strip()


    def _raw_command(self, command):
        '''run the racadm command'''

        if self.login_state != 'OK':
            logging.info('No valid session attempting login')
            if not self.login():
                logging.error('login failed')
                return False

        uri = '{}exec'.format(self.cgiuri)
        payload = '<?xml version=\'1.0\'?><EXEC><REQ>'\
                '<CMDINPUT>racadm {}</CMDINPUT><MAXOUTPUTLEN>0x0fff</MAXOUTPUTLEN>'\
                '</REQ></EXEC>'.format(command)
        content = self._get_response(uri, payload)
        return self._parse_command(content, command)

    def vmdisconnect(self):
        '''run racadm vmdisconnect'''
        status, message = self._raw_command('vmdisconnect')
        if status == RacStatus.RAC_STATUS_FAILED or \
                (status ==  RacStatus.RAC_STATUS_FAILED and \
                message == 'No Virtual Media devices are currently connected.'):
            return True;
        else:
            return False

    def serveraction(self, action):
        '''perform the sever action'''

    def get_arp_table(self):
        '''return arp table'''
        status, message = self._raw_command('arp')
        arp_table = []
        if status == RacStatus.RAC_STATUS_SUCCESS:
            logging.info('reviced arp table:\n{}'.format(message))
            arp_raw = message.split('\n')
            for arp in arp_raw:
                match_group = re.search('\(([0-9a-fA-F\.]+)\)\s+at\s+([0-9a-fA-F\:]+)', arp)
                ip = match_group.group(1)
                mac = match_group.group(2)
                logging.debug('{} -> {}'.format(mac, ip))
                arp_table.append({ 'ip': ip, 'mac': mac })
        return arp_table
    def basic_command(self, command):
        '''run a command that needs no processing'''
        status, message = self._raw_command(command)
        if status == RacStatus.RAC_STATUS_SUCCESS:
            return True
        return False

    def clear_log(self, log_type='rac'):
        if log_type.lower() == 'rac':
            command = 'clrraclog'
        elif log_type.lower() == 'sel':
            command = 'clrsel'
        else:
            logging.warn('log type \'{}\' not supported')
            return False
        return self.basic_command(command)

    def get_asset_tag(self, module='chassis'):
        '''rtrive the Dell assit tag'''
        #i dont have anything to test this on
        return self.basic_command('getassettag -m {}'.format(module))
            
    def get_chassis_name(self):
        '''rtrive the Dell chassis name'''
        #i dont have anything to test this on
        return self.basic_command('chassisname')

    def get_led_state(self):
        '''rtrive the Dell chassis name'''
        #i dont have anything to test this on
        status, message = self._raw_command('getled')
        led_state = False
        if status == RacStatus.RAC_STATUS_SUCCESS:
            led_state = message.split(':')[1].strip()
            logging.debug('led state: {}'.format(led_state))
        return led_state
    def _convert_rac_time(self, date_str):
        '''convert string date of the form Thu Feb  6 06:38:14 2014 to datetime'''
        months = { 'Jan': 1, 'Feb':2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6,
                'Jul':7, 'Aug':8, 'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12}
        date_tmp = date_str.split()
        time_tmp = date_tmp[3].split(':')
        return datetime.datetime(int(date_tmp[4]), int(months[date_tmp[1]]), int(date_tmp[2]), 
                int(time_tmp[0]), int(time_tmp[1]), int(time_tmp[2]))
        
    def get_rac_time(self):
        '''rtrive the Dell chassis name'''
        #i dont have anything to test this on
        status, message = self._raw_command('getractime')
        rac_datetime = False
        if status == RacStatus.RAC_STATUS_SUCCESS:
            rac_datetime = self._convert_rac_time(message)
            logging.info('rac date: {}'.format(rac_datetime.ctime()))

        return rac_datetime

def arg_parse():
    '''argument parsing function'''

    import argparse #we only need this if we are running in cli mode
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-u', '--username', default='root' )
    parser.add_argument('-p', '--password', default='calvin' )
    parser.add_argument('-H', '--hostname', default='localhost' )
    parser.add_argument('-P', '--port', default=443 )
    parser.add_argument('-v', '--verbose', action='count' )
    return parser.parse_args()

def main():
    '''cli component of racadm'''
    args = arg_parse()
    racadm = Racadm(args.hostname, args.username, args.password, 
            args.port, log_level=logging.DEBUG)
    racadm.get_rac_time()

if __name__ == '__main__':
    main()
