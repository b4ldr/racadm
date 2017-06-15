import sys
import getopt
import racadm
import logging

def main(argv):
    user = 'root'
    password = 'calvin'
    log_level = logging.INFO
    opts, args = getopt.getopt(argv,'vu:p:')
    results = dict()
    for opt, arg in opts:
        if opt == '-u':
            user = arg
        elif opt == '-p':
            password = arg
        elif opt == '-v':
            log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    for node in range(1,2):
        node_fqdn = 'drac.prg{0:02d}.l.root-servers.org'.format(node)
        print node_fqdn
        try:
            rac = racadm.Racadm(node_fqdn, user, password)
            ifconfig = rac.basic_command('ifconfig')
            for line in ifconfig.split('\n'):
                tokens = line.split()
                if tokens and tokens[0] == 'eth0':
                    logging.debug('{}: {}'.format(node_fqdn, tokens[4]))
                    results[node_fqdn] = tokens[4]
                    break
        except:
            print '{}: error'.format(node_fqdn)
        finally:  
            rac.logout
    print results
if __name__ == "__main__":
       main(sys.argv[1:])
