#!/usr/bin/env python
import requests
import logging
import re
import datetime
import xml.etree.ElementTree as ET
import sys

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
    RAC_STATUS_INPUT_BUFFER_TOO_SMALL = 0xA
    RAC_STATUS_SYS_OPERATION_FAILED = 0xB
    RAC_STATUS_MEM_ALLOC_FAILED = 0xC
    RAC_STATUS_TIME_FUNC_FAILED = 0xD
    RAC_STATUS_DATA_CONVERSION_FAILED = 0xE
    RAC_STATUS_UNSUPPORTED_CFG = 0xF
    RAC_STATUS_INVALID_FILE = 0x11
    RAC_STATUS_FILE_OPEN_FAILED = 0x12
    RAC_STATUS_FILE_READ_FAILED = 0x13
    RAC_STATUS_FILE_WRITE_FAILED = 0x14
    RAC_STATUS_RAC_NOT_PRESENT = 0x15
    RAC_STATUS_RAC_NOT_READY = 0x16
    RAC_STATUS_IPMI_NOT_READY = 0x17
    RAC_STATUS_LOAD_LIB_FAILED = 0x18
    RAC_STATUS_BUSY = 0x19



class RacadmBase(object):
    '''Object used to interact with iDRAC servers'''

    def __init__(self, hostname='localhost', username='root', password='calvin', port=443, log_level=logging.INFO, verify=False):
        '''
        initialise variables
        @hostname = the iDrac hostname to connect to
        @username = usernem to use for login
        @password = usernem to use for login
        @port = server port to connect to
        @log_level = looggin level to use as implmented by the loggin module
        @verify = whether to verify ssl certificates
        '''

        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.verify = verify
        self.last_message = None
        logging.basicConfig(level=log_level)
        self.session = requests.Session()
        self.cgiuri = 'https://{}:{}/cgi-bin/'.format(self.hostname, self.port)
        self.login_state = None

    def _get_response(self, uri, payload):
        '''
        get a payload from uri
        
        @uri = the uri to talk to
        @payload = the payload to send (as a post)
        '''

        logging.debug('>{}'.format(payload))
        response = self.session.post(uri, data=payload, verify=self.verify)
        logging.debug('<{}'.format(response.content))
        return response.content

    def _search_xml(self, xml_message, element):
        '''
        search an xml message for a specific element
        use the ElementTree libary to get an element matchin .\\${element}

        @xml_message = the xml payload to search
        @element =  the element to find
        '''

        root_element = ET.fromstring(xml_message)
        return root_element.find('.//{}'.format(element)).text

    def _parse_login(self, response):
        '''
        check if we logged in successfuly and set the session cookie if we did

        @response = the respons we need to parse to see if we where successful
        '''

        sid = self._search_xml(response, 'SID')
        self.login_state = self._search_xml(response, 'STATENAME')
        logging.debug('SID:{}, STATE: {}'.format(sid, self.login_state))
        if int(sid) == 0:
            #This could loop for ever kmight want to have a counter
            #possibly a sleep as well
            logging.warn('Got invalid session, try again')
            return self.login()
        if self.login_state == 'OK':
            logging.debug('Login Successful')
            cookie = { 'sid': sid }
            self.session.cookies.update(cookie)
            return True
        logging.warn('Login Failed')
        return False

    def login(self):
        '''
        Login to the drac server and get a cookie. Use details pased during initialisation
        '''
        
        uri = '{}login'.format(self.cgiuri)
        payload = '<?xml version=\'1.0\'?><LOGIN><REQ>'\
                '<USERNAME>{}</USERNAME><PASSWORD>{}</PASSWORD>'\
                '</REQ></LOGIN>'.format(self.username, self.password)
        content = self._get_response(uri, payload)
        return self._parse_login(content)

    def _parse_command(self, response, command):
        '''
        check response and decide if we where successfull

        @response = response to check
        @command = command that was executed, used to add info to log messages
        '''

        command_status = int(self._search_xml(response, 'CMDRC'),16)
        command_output = self._search_xml(response, 'CMDOUTPUT').strip()
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
        self.last_message = command_output 
        return command_status, command_output

    def _convert_rac_time(self, date_str):
        '''
        convert string date of the form Thu Feb  6 06:38:14 2014 to a datetime object
        
        @date_str = string of the form "Thu Feb  6 06:38:14 2014"
        '''
        months = { 'Jan': 1, 'Feb':2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6,
                'Jul':7, 'Aug':8, 'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12}
        date_tmp = date_str.split()
        time_tmp = date_tmp[3].split(':')
        return datetime.datetime(int(date_tmp[4]), int(months[date_tmp[1]]), int(date_tmp[2]), 
                int(time_tmp[0]), int(time_tmp[1]), int(time_tmp[2]))
        
    def _raw_command(self, command):
        '''
        run a raw racadm command
        
        @command = command to run see the following for details
        ftp://ftp.dell.com/Manuals/all-products/esuprt_electronics/esuprt_software/esuprt_remote_ent_sys_mgmt/integrated-dell-remote-access-cntrllr-6-for-monolithic-srvr-v1.7_Reference%20Guide_en-us.pdf
        '''

        if self.login_state != 'OK':
            logging.debug('No valid session attempting login')
            if not self.login():
                logging.error('login failed')
                return False

        uri = '{}exec'.format(self.cgiuri)
        payload = '<?xml version=\'1.0\'?><EXEC><REQ>'\
                '<CMDINPUT>racadm {}</CMDINPUT><MAXOUTPUTLEN>0x0fff</MAXOUTPUTLEN>'\
                '</REQ></EXEC>'.format(command)
        content = self._get_response(uri, payload)
        return self._parse_command(content, command)

    def basic_command(self, command):
        '''
        command wrapper to preform simple checks
        
        @command = command to run
        '''
        status, message = self._raw_command(command)
        if status == RacStatus.RAC_STATUS_SUCCESS:
            return message
        return False


class Racadm(RacadmBase):
    '''base clase for an object'''

    def __init__(self, hostname='localhost', username='root', password='calvin', port=443, log_level=logging.INFO, verify=False):
        '''
        initialise variables
        @hostname = the iDrac hostname to connect to
        @username = usernem t  use for login
        @password = usernem to use for login
        @port = server port to connect to
        @log_level = looggin level to use as implmented by the loggin module
        @verify = whether to verify ssl certificates
        '''
        super(Racadm, self).__init__(hostname, username, password, port, log_level, verify)

    def set_led(self, state):
        '''
        set the led to a specific state
        
        @state = the state you want the led to be in
        '''
        action = { 'off': 0, 'no_blink': 0, 'no_blinking': 0, 'on': 1, 'blink': 1, 'blinking': 1,
                }.get(state, state)
        if action not in [0, 1]:
            logging.warn('set_let not support action {}'.format(state))
            return False
        return self.basic_command('setled -l {}'.format(action))

    def server_action(self, action='powerstatus'):
        action = {
                'status': 'powerstatus',
                'cycle': 'powercycle',
                'up': 'powerup',
                'down': 'powerdown',
                'reset': 'hardreset', 
        }.get(action.lower(), action.lower())

        valid_actions = ['powerstatus', 'powercycle', 'powerup', 'powerdown', 'hardreset' ]
        if action not in valid_actions:
            logging.warn('action {} not supported'.format(action))
            return False
        return self.basic_command('serveraction {}'.format(action))

    def ping(self, address, address_family=4):
        '''
        ping an ip from the drac interface

        @address = the address to ping
        @address_family = the ip version to use
        '''
        if int(address_family) not in [4,6]:
            logging.warn('address_family {} not supported'.format(address_family))
            return False
        command = 'ping {}'.format(address)
        if int(address_family) == 6:
            command = 'ping6 {}'.format(address)
        return self.basic_command(command)

    def traceroute(self, address, address_family=4):
        '''
        traceroute an ip from the drac interface

        @address = the address to ping
        @address_family = the ip version to use
        '''
        #didn't work for me i think it is timeing out
        if int(address_family) not in [4,6]:
            logging.warn('address_family {} not supported'.format(address_family))
            return False
        command = 'traceroute {}'.format(address)
        if int(address_family) == 6:
            command = 'traceroute6 {}'.format(address)
        return self.basic_command(command)

    def vmdisconnect(self):
        '''run racadm vmdisconnect'''
        status, message = self._raw_command('vmdisconnect')
        if status == RacStatus.RAC_STATUS_FAILED or \
                (status ==  RacStatus.RAC_STATUS_FAILED and \
                message == 'No Virtual Media devices are currently connected.'):
            return True;
        else:
            return False

    def _vflashd(self, action):
        raise NotImplementedError('Dont have a system to test this on') 

    def _vflashd(self, action):
        if action not in ['status', 'initialize']:
            logging.warn('action {} not supported'.format(action))
            return False
        return self.basic_command('vflashsd {}'.format(action))

    def vflash_status(self):
        return self._vflashd('status')

    def vflash_initialise(self):
        return self._vflashd('initialize')

    def vflash_initialize(self):
        '''american spelling'''
        return self._vflashd('initialize')

    def get_arp_table(self):
        '''
        parse the arp table of the drac interface
        '''
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

    def clear_log(self, log_type='rac'):
        '''
        clear a drac log

        @log_type = the log you want to clear.  allowed values are rac and sel
        '''
        if log_type.lower() == 'rac':
            command = 'clrraclog'
        elif log_type.lower() == 'sel':
            command = 'clrsel'
        else:
            logging.warn('log type \'{}\' not supported')
            return False
        return self.basic_command(command)

    def get_asset_tag(self, module='chassis'):
        '''
        retrive the asset tag of a specific module

        @module = the module of the asset tag you want

        WARN: untested
        '''
        #i dont have anything to test this on
        logging.warn('This method is untested')
        return self.basic_command('getassettag -m {}'.format(module))
            
    def get_chassis_name(self):
        '''
        retrive the chassis name of a specific module
        WARN: untested
        '''
        #i dont have anything to test this on
        logging.warn('This method is untested')
        return self.basic_command('chassisname')

    def get_sensor_info(self):
        '''
        Retrive the snesor details from drac card
        '''
        #im not parsing this output. its to fucked 
        return self.basic_command('getsensorinfo')

    def get_service_tag(self):
        '''get the Dell service tag'''
        return self.basic_command('getsvctag')

    def get_usc_version(self):
        '''get the usc versiob'''
        return self.basic_command('getuscversion')

    def rac_reset(self):
        '''Reset the drac card'''
        return self.basic_command('racreset')

    def get_software_inventory(self):
        '''return a dictionary containing the drac sowftare inventory'''
        inventory = []
        item = {}
        result = self.basic_command('swinventory')
        for line in result.split('\n'):
            if '--------------------------------------' in line:
                inventory.append(item)
                item = {}
            elif '=' in line:
                key, value = line.split('=')
                item.update({key.strip().replace(' ', '_') : value.strip()})
                
        return inventory

    def get_version(self):
        '''
        return a dictionary containing the software versions of the various componets 
        e.g. bios, drac & usc
        '''
        versions = {}
        result = self.basic_command('getversion')
        for line in result.split('\n'):
            if '=' in line:
                version = line.split('=')
                version_type = version[0].strip().replace(' ','_').lower()
                versions[version_type] = version[1].strip()
        return versions
 
    def get_session_info(self):
        '''
        rturn a dictionary containing information about the active sessions
        '''
        sessions = []
        results = self.basic_command('getssninfo')
        if results:
            for line in results.split('\n'):
                #Currently the title splits to 7 elements so this should work
                if len(colums) == 6:
                    #Not sure what D stands for here but may as well keep it
                    date_str = '{}{}'.format(colums[4].replace('/',''),colums[5].replace(':',''))
                    print date_str
                    sessions.append({
                        'd': colums[0], 
                        'type': colums[1], 
                        'user': colums[2], 
                        'ip': colums[3], 
                        'date': datetime.datetime.strptime(date_str,'%m%d%Y%H%M%S' )
                        })

        return sessions

    def get_log(self, log_type):
        ''' get the Dell specified log type'''
        logging.warn('This method is untested')
        #getraclog returns no data
        #getsel and gettracelog both responded with bad xml and
        #ERROR: Unable to allocate memory for operation.
        #It also sets CMDRC to 0x0 which is anoying
        return self.basic_command({ 
                'rac' : 'getraclog',
                'sel' : 'getsel',
                'trace' : 'gettracelog',
                'lc' : 'lclog',
        }.get(log_type.lower(), 'getraclog'))

    def _basic_table_command(self, command):
        '''
        very generic table parser.  tries to parse the output and return more 
        sendible python object
        
        @command to run
        '''
        parsed_table ={}
        parsed_items = {}
        section = None
        status, message = self._raw_command(command)
        if status == RacStatus.RAC_STATUS_SUCCESS:
            for line in message.split('\n'):
                if ':' in line and '=' not in line:
                    #we are in a new section
                    sections = line.split(':')
                    #this is a hack for the HW inventory
                    if sections[0] == '[InstanceID':
                        section = sections[1].strip().replace(' ','_').replace(']',' ')
                    else:
                        section = sections[0].strip().replace(' ','_')
                    parsed_table[section] = {}
                elif '=' in line:
                    key, value = line.split('=')
                    parsed_table[section].update({ 
                        key.strip().replace(' ','_') :
                        value.strip()})
            logging.debug('parsed {}: {}'.format(command, parsed_table)) 
        return parsed_table 

    def get_system_info(self):
        '''return a dictionory of the drac system information'''
        return self._basic_table_command('getsysinfo')

    def get_network_config(self):
        '''return a dictionory of the drac network config'''
        return self._basic_table_command('getniccfg')

    def get_hardware_inventory(self):
        '''return a dictionory of the drac hardware information'''
        return self._basic_table_command('hwinventory')

    def get_led_state(self):
        '''return the state of the server status led'''
        #i dont have anything to test this on
        status, message = self._raw_command('getled')
        led_state = False
        if status == RacStatus.RAC_STATUS_SUCCESS:
            led_state = message.split(':')[1].strip()
            logging.debug('led state: {}'.format(led_state))
        return led_state

    def get_rac_time(self):
        '''
        return a datetime object representing the rac system time
        '''
        #i dont have anything to test this on
        status, message = self._raw_command('getractime')
        rac_datetime = False
        if status == RacStatus.RAC_STATUS_SUCCESS:
            rac_datetime = self._convert_rac_time(message)
            logging.info('rac date: {}'.format(rac_datetime.ctime()))

        return rac_datetime



class RacadmConfig(RacadmBase):
    '''base clase for an object'''

    def __init__(self, group, hostname='localhost', username='root', password='calvin', port=443, 
            log_level=logging.INFO, verify=False, has_index=False):
        '''
        initialise variables
        @hostname = the iDrac hostname to connect to
        @username = usernem to use for login
        @password = usernem to use for login
        @port = server port to connect to
        @log_level = looggin level to use as implmented by the loggin module
        @verify = whether to verify ssl certificates
        '''
        super(RacadmConfig, self).__init__(hostname, username, password, port, log_level, verify)
        self.group = group
        self.has_index = has_index
        #these systems need an index
        if self.group in ['cfgUserAdmin', 'cfgEmailAlert', 'cfgLdapRoleGroup', 'cfgStandardSchema', 
                'cfgIpmiPef', 'cfgServerPowerSupply', 'cfgVFlashPartition', 'cfgUserDomain', 'cfgSensorRedundancy']:
            self.has_index = True

    def _parse_config_group(self, message):
        '''
        used to parse the date from _get_config.  which is mainly of the form 
        key=value
        however readonly valuse are prefixed with '#' so we chop that as well
        '''
        config = {}
        for line in message.split('\n'):
            if '=' in line:
                key, value = line.lstrip('#').split('=')
                config[key.strip()] = value.strip()
        return config

    def _get_config(self, conf_group, conf_object=None, conf_index=None):
        '''
        generic function to fetch config of the form
        racadm getconfig -g ${conf_group} -o ${conf_object} -i ${conf_index}

        @conf_group = the config group to query
        @conf_object = the config object to query
        @conf_index = the config index to query
        '''
        command = 'getconfig -g {}'.format(conf_group)
        if conf_object:
            command += ' -o {}'.format(conf_object)
        if conf_index:
            command += ' -i {}'.format(conf_index)
        return self.basic_command(command)

    def get_index(self, conf_index, conf_object=None):
        '''
        genreic function to get a config item that requiers an index
        
        @conf_group = group to query
        @conf_index = index to query
        @conf_object = object to query
        '''
        if not self.has_index:
            raise TypeError('{} does not support Indexes use get() instead'.format(self.group))
        if conf_object:
            return self._get_config(self.group, conf_object, conf_index)
        return self._parse_config_group(self._get_config(self.group, conf_object, conf_index))

    def get(self, conf_object=None):
        '''
        genreic function to get a config item that requiers no index
        
        @conf_object = object to query
        '''
        if self.has_index:
            raise TypeError('{} must specifiy index use get_index() instead'.format(self.group))
        if conf_object:
            return self._get_config(self.group, conf_object)
        return self._parse_config_group(self._get_config(self.group))

    def _set_config(self, conf_value, conf_object=None, conf_index=None):
        '''
        generic function to fetch config of the form
        racadm setconfig -g ${conf_group} -o ${conf_object} -i ${conf_index}

        @conf_group = the config group to query
        @conf_object = the config object to query
        @conf_index = the config index to query
        '''
        command = 'config -g {} -o {}'.format(self.group, conf_object)
        if conf_index:
            command += ' -i {}'.format(conf_index)
        return self.basic_command('{} {}'.format(command, conf_value))

    def set_index(self, conf_object, conf_index, conf_value):
        '''
        genreic function to set a config item that requiers an index
        
        @conf_group = group to query
        @conf_index = index to query
        @conf_object = object to query
        '''
        if not self.has_index:
            raise TypeError('{} does not support Indexes use set() instead'.format(self.group))
        return self._set_config(conf_value, conf_object, conf_index)

    def set(self, conf_object, conf_value):
        '''
        genreic function to set a config item that requiers no index
        
        @conf_object = object to query
        '''
        if self.has_index:
            raise TypeError('{} must specifiy index use set_index() instead'.format(self.group))
        return self._set_config(conf_value, conf_object)


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
    print racadm.get_session_info()

if __name__ == '__main__':
    main()
