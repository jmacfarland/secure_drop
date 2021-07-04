#! /usr/bin/env python3
import asyncio
import socket
import threading
from session import Session

def debug( msg ):
    print "[%s] %s" % ( str(threading.currentThread().getName()), msg )

class Peer():
    def __init__(self, host="localhost", port=10000):
        self.debug = True
        self.shutdown = False
        self.host = host
        self.port = port
        self.backlog = 1
        self.session = None
        self.handlers = {
            MESG: self._handle_recv_message,
        }

    def _handle(self, clientsock):
        self._debug('Connected to ' + str(clientsock.getpeername()))
        host, port = clientsock.getpeername()
        peerconn = PeerConnection(host, port, clientsock, self.debug)

        try:
            msgtype, msgdata = conn.recv_data()
            if msgtype: msgtype = msgtype.upper()
            if msgtype not in self.handlers:
                self._debug('Not handled... %s: %s'%(msgtype, msgdata))
            else:
                self._debug('Handling... %s: %s'%(msgtype, msgdata))
                self.handlers[msgtype](peerconn, msgdata)
        except KeyboardInterrupt:
            raise
        except:
            if self.debug:
                traceback.print_exc()

        self._debug('Disconnecting ' + str(clientsock.getpeername()))
        peerconn.close()

    def _handle_recv_message(self, conn, data):
        self.debug("HANDLE RECV MESSAGE")
        print(data)

    def makeserversocket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(self.backlog)
        return s

    def _debug(self, msg):
        if self.debug:
            debug(msg)

    def mainloop(self):
        s = self.makeserversocket()
        s.settimeout(2)
        self._debug('Server started: (%s:%d)'%(self.host,self.port))

        while not self.shutdown:
            try:
                self._debug('Listening for connections...')
                clientsock, clientaddr = s.accept()
                clientsock.settimeout(None)

                t = threading.Thread(target=self._handlepeer, args=[clientsock])
                t.start()

            except KeyboardInterrupt:
                print('KeyboardInterrupt: stopping')
                self.shutdown = True
                continue
            except:
                if self.debug:
                    traceback.print_exc()
                    continue

        self._debug('Exiting')
        s.close()

class PeerConnection:
    #Handle session stuff and decoding messages
    # this class largely adapted from btpeer.py -> BTPeerConnection
    def __init__(self, host, port, sock=None, debug=False):
        self.debug = debug
        if not sock:
    	    self.s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    	    self.s.connect( ( host, int(port) ) )
    	else:
    	    self.s = sock

    #--------------------------------------------------------------------------
    def senddata( self, msgtype, msgdata ):
    #--------------------------------------------------------------------------
    	"""
    	senddata( message type, message data ) -> boolean status

    	Send a message through a peer connection. Returns True on success
    	or False if there was an error.
    	"""

    	try:
    	    msg = self.__makemsg( msgtype, msgdata )
    	    self.sd.write( msg )
    	    self.sd.flush()
    	except KeyboardInterrupt:
    	    raise
    	except:
    	    if self.debug:
    		traceback.print_exc()
    	    return False
    	return True

    #--------------------------------------------------------------------------
    def recvdata( self ):
    #--------------------------------------------------------------------------
        """
    	recvdata() -> (msgtype, msgdata)

    	Receive a message from a peer connection. Returns (None, None)
    	if there was any error.
    	"""
        try:
    	    msgtype = self.sd.read( 4 )
    	    if not msgtype: return (None, None)

                lenstr = self.sd.read( 4 )
    	    msglen = int(struct.unpack( "!L", lenstr )[0])
    	    msg = ""

    	    while len(msg) != msglen:
    		data = self.sd.read( min(2048, msglen - len(msg)) )
    		if not len(data):
    		    break
    		msg += data

    	    if len(msg) != msglen:
    		return (None, None)

    	except KeyboardInterrupt:
    	    raise
    	except:
    	    if self.debug:
    		traceback.print_exc()
    	    return (None, None)

    	return ( msgtype, msg )

    def _debug(self, msg):
        if self.debug:
            debug(msg)

def main():
    p = Peer(port=10003)

if __name__ == "__main__":
    main()
