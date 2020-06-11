# You may redistribute this program and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import print_function
import sys
import os
import socket
import errno
import hashlib
import json
import threading
import time
try: import queue 
except: import Queue as queue
import random
import string
try: from cjdnsadmin.bencode import *
except: from bencode import *

BUFFER_SIZE = 69632
KEEPALIVE_INTERVAL_SECONDS = 2

def tostr(d):
    if sys.version_info[0] < 3: return d
    r = {}
    for k,v in d.items():
      try:
        r[k.decode()] = v.decode()
      except:
        r[k.decode()] = v
    return r

class Session():
    """Current cjdns admin session"""

    def __init__(self, socket):
        self.socket = socket
        self.queue = queue.Queue()
        self.messages = {}

    def disconnect(self):
        self.socket.close()

    def getMessage(self, txid):
        # print(self, txid)
        return _getMessage(self, txid)

    def functions(self):
        print(self._functions)


def _randomString():
    """Random string for message signing"""

    s = ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for x in range(10))
    if sys.version_info[0] >= 3:
      return s.encode('ascii')
    return s

def _callFunc(session, funcName, password, args):
    """Call custom cjdns admin function"""

    txid = _randomString()
    sock = session.socket
    sock.send(b'd1:q6:cookie4:txid10:' + txid + b'e')
    msg = _getMessage(session, txid)
    cookie = msg[b'cookie']
    txid = _randomString()
    req = {
        'q': funcName,
        'hash': hashlib.sha256(password + cookie).hexdigest(),
        'cookie': cookie,
        'args': args,
        'txid': txid
    }

    if password:
        req['aq'] = req['q']
        req['q'] = 'auth'
        reqBenc = bencode(req)
        req['hash'] = hashlib.sha256(reqBenc).hexdigest()

    reqBenc = bencode(req)
    sock.send(reqBenc)
    return _getMessage(session, txid)


def _receiverThread(session):
    """Receiving messages from cjdns admin server"""

    timeOfLastSend = time.time()
    timeOfLastRecv = time.time()
    try:
        while True:
            if (timeOfLastSend + KEEPALIVE_INTERVAL_SECONDS < time.time()):
                if (timeOfLastRecv + 10 < time.time()):
                    raise Exception("ping timeout")
                session.socket.send(
                    b'd1:q18:Admin_asyncEnabled4:txid8:keepalive')
                timeOfLastSend = time.time()

            # Did we get data from the socket?
            got_data = False

            while True:
                # This can be interrupted and we need to loop it.

                try:
                    data = session.socket.recv(BUFFER_SIZE)
                except (socket.timeout):
                    # Stop retrying, but note we have no data
                    break
                except socket.error as e:
                    if e.errno != errno.EINTR:
                        # Forward errors that aren't being interrupted
                        raise
                    # Otherwise it was interrupted so we try again.
                else:
                    # Don't try again, we got data
                    got_data = True
                    break

            if not got_data:
                # Try asking again.
                continue


            try:
                benc,f = bdecode(data)
            except (KeyError, ValueError):
                print("error decoding [" + data + "]")
                continue

            if benc[b'txid'] == 'keepaliv':
                if benc['asyncEnabled'] == 0:
                    raise Exception("lost session")
                timeOfLastRecv = time.time()
            else:
                # print("putting to queue " + str(benc))
                session.queue.put(benc)

    except KeyboardInterrupt:
        print("interrupted")
        import thread
        thread.interrupt_main()
    except Exception as e:
        # Forward along any errors, before killing the thread.
        session.queue.put(e)


def _getMessage(session, txid):
    """Getting message associated with txid"""

    while True:
        if txid in session.messages:
            msg = session.messages[txid]
            del session.messages[txid]
            return msg
        else:
            # print("getting from queue")
            try:
                # apparently any timeout at all allows the thread to be
                # stopped but none make it unstoppable with ctrl+c
                next = session.queue.get(timeout=100)
            except queue.Empty:
                continue

            if isinstance(next, Exception):
                # If the receiveing thread had an error, throw one here too.
                raise next

            if b'txid' in next:
                session.messages[next[b'txid']] = next
                # print("adding message [" + str(next) + "]")
            else:
                print("message with no txid: " + str(next))


def _functionFabric(func_name, argList, oargs, oargNames, password):
    """Function fabric for Session class"""

    def functionHandler(self, *args, **kwargs):
        call_args = {}
        
        pos = 0
        for value in args:
            if (pos < len(argList)):
                call_args[argList[pos]] = value
                pos += 1
            elif (pos < len(argList) + len(oargNames)):
                call_args[oargNames[pos - len(argList)]] = value
            else:
                print("warning: extraneous argument passed to function",func_name,value)

        for (key, value) in kwargs.items():
            if key not in oargs:
                if key in argList:
                    # this is a positional argument, given a keyword name
                    # that happens in python.
                    # TODO: we can't handle this along with unnamed positional args.
                    pos = argList.index(key)
                    call_args[argList[pos]] = value
                    continue
                else:
                    print("warning: not an argument to this function",func_name,key)
                    print(oargs)
            else:
                # TODO: check oargs[key] type matches value
                # warn, if doesn't
                call_args[key] = value

        return _callFunc(self, func_name, password, call_args)

    if sys.version_info[0] >= 3:
      functionHandler.__name__ = func_name.decode()
    else:
      functionHandler.__name__ = func_name
    return functionHandler


def connect(ipAddr, port, password):
    """Connect to cjdns admin with this attributes"""

    if sys.version_info[0] >= 3:
      password = password.encode('ascii')
    print('connect:',ipAddr,port,password)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ipAddr, port))
    sock.settimeout(2)

    # Make sure it pongs.
    sock.send(b'd1:q4:pinge')
    data = sock.recv(BUFFER_SIZE)
    if (not data.endswith(b'1:q4:ponge')):
        raise Exception(
            "Looks like " + ipAddr + ":" + str(port) +
            " is to a non-cjdns socket.")

    # Get the functions and make the object
    page = 0
    availableFunctions = {}
    while True:
        sock.send(b'd1:q24:Admin_availableFunctions4:argsd4:pagei%deee'%page)
        data = sock.recv(BUFFER_SIZE)
        benc,f = bdecode(data)
        #print('benc=',benc)
        for func in benc[b'availableFunctions']:
            availableFunctions[func] = benc[b'availableFunctions'][func]
        if not b'more' in benc:
            break
        page = page+1

    funcArgs = {}
    funcOargs = {}

    for (i, func) in availableFunctions.items():
        items = func.items()

        # required args
        argList = []
        # optional args
        oargs = {}
        # order of optional args for python-style calling
        oargNames = []
        
        for (arg,atts) in items:
            if atts[b'required']:
                argList.append(arg)
            else:
                oargs[arg] = atts[b'type']
                oargNames.append(arg)

        if sys.version_info[0] >= 3:
          k = i.decode()
        else:
          k = i
        setattr(Session, k, _functionFabric(
            i, argList, oargs, oargNames, password))

        funcArgs[i] = argList
        funcOargs[i] = oargs

    session = Session(sock)

    kat = threading.Thread(target=_receiverThread, args=[session])
    kat.setDaemon(True)
    kat.start()

    # Check our password.
    ret = _callFunc(session, "ping", password, {})
    if ('error' in ret):
        raise Exception(
            "Connect failed, incorrect admin password?\n" + str(ret))

    session._functions = ''

    funcOargs_c = {}
    for func in funcOargs:
        funcOargs_c[func] = list(
            [key + b'=' + str(value).encode('ascii')
                for (key, value) in funcOargs[func].items()])

    for func in availableFunctions:
        f = func.decode()
        session._functions += (
            f + '(' + b', '.join(funcArgs[func] + funcOargs_c[func]).decode() + ')\n')

    return session


def connectWithAdminInfo(path = None):
    """Connect to cjdns admin with data from user file"""

    if path is None:
        path = os.path.expanduser('~/.cjdnsadmin')
    try:
        with open(path, 'rb') as adminInfo:
            data = json.load(adminInfo)
    except IOError:
        sys.stderr.write("""Please create a file named .cjdnsadmin in your
home directory with
ip, port, and password of your cjdns engine in json.
for example:
{
    "addr": "127.0.0.1",
    "port": 11234,
    "password": "You tell me! (Search in ~/cjdroute.conf)"
}
""")
        raise

    return connect(data['addr'], data['port'], data['password'])
