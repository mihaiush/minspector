import Milter
import time
import traceback
import os
import re
import base64
import email.parser
import email.policy
import sys
import logging

BODY_MAX = 100 * 1024
DROP_MESSAGE = True
SPOOL_DIR = "/var/spool/minspector"

class Logger(logging.Logger):
    def __init__(self, name):
        logging.Logger.__init__(self, name)
        self.setLevel(logging.INFO)
        self.lh = logging.StreamHandler(sys.stdout)
        self.addHandler(self.lh)
        self.enable_timestamp(False)
    def enable_debug(self):
        self.setLevel(logging.DEBUG)
    def enable_timestamp(self, ts=True):
        if ts:
           f = '%(asctime)-15s %(levelname)s %(message)s'
        else:
            f = '%(levelname)s %(message)s'
        self.lh.setFormatter(logging.Formatter(f))
logging.setLoggerClass(Logger)
LOG = logging.getLogger(__name__)

TEST_LIST = []
class Test:
    def __init__(self, label, policy, message='MI-{id}-{label}-{stage}'):
        self.__label = label
        self.__policy = policy.upper()
        self.__message = message
        self.__enable = True
        TEST_LIST.append(self)
    def enable(self):
        self.__enable = True
    def disable(self):
        self.__enable = False
    def main(self, email):
        return False
    def line(self, email, line):
        return False

RE_B64BAD = re.compile('[\+\/=]')
def b64str(x):
    if type(x) != bytes:
        x = str(x).encode()
    return RE_B64BAD.sub('', base64.b64encode(x).decode('ascii', 'ignore'))

def make_id(x=24):
    ts = str(int(1000000*time.time()))
    ts = b64str(ts)
    r = os.urandom(x)
    r = b64str(r)
    return r[0:x-len(ts)] + ts

def parse_headers(headers):
    r = {'received':[]}
    for h,v in headers:
        h = h.lower()
        v = v.replace('\n', '')
        v = v.replace('\t', ' ')
        if h == 'received':
            r['received'].append(v)
        else:
            r[h] = v
    return r

class Client:
    def __init__(self, ip, port, name):
        self.ip = ip
        self.port = port
        self.name = name

class MInspector(Milter.Base):

    exit_policy = ['ACCEPT', 'REJECT', 'DEFER', 'DISCARD']

    def debug(self, label, *msg):
        if LOG.getEffectiveLevel() == logging.DEBUG:
            l = '[{}]'.format(label.upper())
            for m in msg:
                l = '{}\n{}'.format(l, m)
            LOG.debug(l)

    def log(self, msg, verbose=False):
        msg = '{} [{}:{}] {}'.format(self.id, self.test_label, self.test_stage, msg)
        if verbose:
            msg = '{} {{client:{}[{}], helo:{}, mail_from:{}, rcpt_to:{}}}'.format(msg, self.client.name, self.client.ip, self.helo, self.mail_from, ','.join(self.rcpt_to))
        LOG.info(msg)
        
    def exit(self, t):
        policy = t._Test__policy
        message = t._Test__message
        self.log(policy, verbose=True)
        s = self.test_stage[0].upper()
        msg=message.format(id=self.id, label=self.test_label, stage=s)
        if policy == 'REJECT':
            self.setreply('554', msg=msg)
            return Milter.REJECT
        elif policy == 'DEFER':
            self.setreply('451', msg=msg)
            return Milter.TEMPFAIL
        elif policy == 'DISCARD':
            return Milter.DISCARD
        return Milter.ACCEPT

    @Milter.noreply
    def connect(self, ipname, family, hostaddr):
        self.client = Client(hostaddr[0], hostaddr[1], ipname)
        self.debug('connect', '{} [{}:{}]'.format(self.client.name, self.client.ip, self.client.port))
        self.skip = bool(self._protocol & Milter.P_SKIP)
        self.debug('connect', 'skip {}'.format(self.skip))
        return Milter.CONTINUE

    @Milter.noreply
    def hello(self, hostname):
        self.helo = hostname
        self.debug('hello', self.helo)
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, f, *extra):
        # per-message init
        self.id = make_id(30)
        self.message = email.parser.BytesFeedParser(policy=email.policy.SMTPUTF8)
        self.body_size = 0
        self.rcpt_to = []
        self.headers_raw = []
        self.test_label = 'NA'
        self.test_stage = 'NA'
        #
        self.mail_from = f.lower()
        self.debug('envfrom', self.mail_from, extra)
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, t, *extra):
        self.rcpt_to.append(t.lower())        
        self.debug('envrcpt', self.rcpt_to, extra)
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, h, v):
        self.headers_raw.append([h, v])
        bh = '{}: {}\r\n'.format(h, v).encode('ascii', 'ignore')
        self.message.feed(bh)
        self.debug('header', '{}={}'.format(h,v))
        return Milter.CONTINUE

    @Milter.noreply
    def eoh(self):
        self.message.feed('\r\n'.encode('ascii', 'ignore'))
        return Milter.CONTINUE

    def body(self, chunk):
        try:
            if self.body_size < BODY_MAX:
                self.message.feed(chunk)
                self.body_size = self.body_size + len(chunk)
                self.debug('body', 'chunk: {}b, data: {}b'.format(len(chunk), self.body_size))
            elif self.skip:
                return Milter.SKIP
        except:
            LOG.error('body:\n{}'.format(traceback.format_exc()))
            self.log('error-debug', verbose=True)
        return Milter.CONTINUE

    def eom(self):
        try:
            self.message = self.message.close()
            # self.text = preabble + all parts with content-type text/*
            self.text = []
            if self.message.preamble:
                self.debug('email-preamble', self.message.preamble)
                self.text = self.text + self.message.preamble.split('\r\n')
            for part in self.message.walk():
                if part.get_content_type().startswith('text/'):
                    text = part.get_payload(decode=True).decode('utf-8', 'ignore')
                    self.debug('email-part', text)
                    self.text = self.text + text.split('\r\n')
            # headers [(h,v)] -> {h:v}
            # if error headers -> milter headers
            try:
                self.headers = parse_headers(self.message.items())
                self.headers_raw = False
            except:
                l = '{}, eom-parseheaders:'.format(self.id)
                for h in self.headers_raw:
                    l = '{}\n{}'.format(l, h)
                l = '{}\n{}'.format(l,traceback.format_exc())
                LOG.error(l)
                self.log('error-debug', verbose=True)
                self.headers = self.headers_raw
                self.headers_raw = True
            # delete EmailMessage object
            if DROP_MESSAGE:
                del(self.message)
            # run main() method of each test
            for t in TEST_LIST:
                self.test_label = t._Test__label
                self.test_stage = 'main'
                if t.main(self) :
                    if t._Test__policy in self.exit_policy:
                        return self.exit(t)
                    self.log(t._Test__policy, verbose=True)
            # for each line run line() method of each test
            # disable test if match
            for l in self.text:
                enable = False
                for t in TEST_LIST:
                    if t._Test__enable:
                        enable = True
                        self.test_label = t._Test__label
                        self.test_stage = 'line'
                        if t.line(self, l) :
                            if t._Test__policy in self.exit_policy:
                                return self.exit(t)
                            t._Test__enable = False
                            self.log(t._Test__policy, verbose=True)
                # terminate if all tests are disabled
                if not enable:
                    break
        except:
            LOG.error('body:\n{}'.format(traceback.format_exc()))  
            self.log('error-debug', verbose=True)
        return Milter.ACCEPT


if __name__ == '__main__':

    LOG.enable_timestamp()
    #LOG.enable_debug()

    class test(Test):
        def main(self, email):
            return True
    test('0000', 'LOG')    

    Milter.factory = MInspector
    milter = 'MINSPECTOR'
    LOG.info('Starting {}[{}]'.format(milter, os.getpid()))
    Milter.runmilter(milter, '/run/minspector/sock')

