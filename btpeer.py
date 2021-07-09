#!/usr/bin/python

# btpeer.py

import socket
import struct
import threading
import time
import traceback
import json

from session import Session


def btdebug( msg ):
	# """ Prints a messsage to the screen with the name of the current thread """
	print("[%s] %s" % ( str(threading.currentThread().getName()), msg ))


#==============================================================================
class BTPeer:
	# """ Implements the core functionality that might be used by a peer in a
	# P2P network.
	# """

	#--------------------------------------------------------------------------
	def __init__( self, maxpeers, serverport, myid=None, serverhost = None ):
	#--------------------------------------------------------------------------
		# Initializes a peer servent (sic.) with the ability to catalog
		# information for up to maxpeers number of peers (maxpeers may
		# be set to 0 to allow unlimited number of peers), listening on
		# a given server port , with a given canonical peer name (id)
		# and host address. If not supplied, the host address
		# (serverhost) will be determined by attempting to connect to an
		# Internet host like Google.

		self.debug = True

		self.maxpeers = int(maxpeers)
		self.serverport = int(serverport)
		if serverhost: self.serverhost = serverhost
		else: self.__initserverhost()

		if myid: self.myid = myid
		else: self.myid = '%s:%d' % (self.serverhost, self.serverport)

		self.peerlock = threading.Lock()  # ensure proper access to
									# peers list (maybe better to use
									# threading.RLock (reentrant))
		self.peers = {}        # peerid ==> (host, port) mapping

		self.peersessions = {} # session ID -> Session

		self.shutdown = False  # used to stop the main loop

		self.handlers = {
			'SESH': self.__handle_begin_session,
			'PMSG': self.__handle_plain_message,
			'CMSG': self.__handle_cipher_message,
		}
		self.router = self.simplerouter

	def simplerouter(self, peerid):
		#routes message directly to peer, if peer is in known peers
		host, port = self.peers[peerid]
		return (peerid, host, port)

	def __handle_begin_session(self, peerconn, msgdata):
		self.__debug("Opening session with peer %s"%peerconn.id)
		#only make new IF not exist / TTL expired? later improvement
		self.peersessions[peerconn.id] = Session()
		if not self.peersessions[peerconn.id].recv_pubkey(msgdata.decode()):
			self.__debug("Open session failed")
		peerconn.senddata('REPL', self.peersessions[peerconn.id].send_pubkey())

	def __handle_plain_message(self, peerconn, msgdata):
		#for testing purposes, should not be used due to being plaintext
		print("Received msg: %s"%msgdata)

	def __handle_cipher_message(self, peerconn, msgdata):
		#error if no open session for peerconn.id
		#otherwise, decrypt msgdata with session
		plain_msg = self.peersessions["one"].recv_msg(msgdata)
		self.__debug(plain_msg)

	def send_cipher_message(self, peerid, message):
		#encrypt message
		msg_cipher = self.peersessions[peerid].send_msg(message)
		#send to peer
		self.sendtopeer(peerid, 'CMSG', msg_cipher)

	def begin_session_with(self, peerid):
		self.__debug("Sending request to open session to %s"%peerid)
		self.peersessions[peerid] = Session()
		resp = self.sendtopeer(peerid, 'SESH', self.peersessions[peerid].send_pubkey())
		if not self.peersessions[peerid].recv_pubkey(resp[0][1]): #must be [0][1] to get the actual response message
			self.__debug("Open session failed")


	#--------------------------------------------------------------------------
	def __initserverhost( self ):
	#--------------------------------------------------------------------------
		# """ Attempt to connect to an Internet host in order to determine the
		# local machine's IP address.
		#
		# """
		s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
		s.connect( ( "www.google.com", 80 ) )
		self.serverhost = s.getsockname()[0]
		s.close()



	#--------------------------------------------------------------------------
	def __debug( self, msg ):
	#--------------------------------------------------------------------------
		if self.debug:
			btdebug( msg )



	#--------------------------------------------------------------------------
	def __handlepeer( self, clientsock ):
	#--------------------------------------------------------------------------
		# """
		# handlepeer( new socket connection ) -> ()
		#
		# Dispatches messages from the socket connection
		# """

		self.__debug( 'New child ' + str(threading.currentThread().getName()) )
		self.__debug( 'Connected ' + str(clientsock.getpeername()) )

		host, port = clientsock.getpeername()
		#CHANGE THIS:
		peerid = "one"
		peerconn = BTPeerConnection( peerid, host, port, clientsock, debug=False )

		try:
			msgtype, msgdata = peerconn.recvdata()
			if msgtype: msgtype = msgtype.upper()
			if msgtype not in self.handlers:
				self.__debug( 'Not handled: %s: %s' % (msgtype, msgdata) )
			else:
				self.__debug( 'Handling peer msg: %s: %s' % (msgtype, msgdata) )
				self.handlers[ msgtype ]( peerconn, msgdata )
		except KeyboardInterrupt:
			raise
		except:
			if self.debug:
				traceback.print_exc()

		self.__debug( 'Disconnecting ' + str(clientsock.getpeername()) )
		self.__debug( 'Ending ' + str(threading.currentThread().getName()) )
		peerconn.close()

		# end handlepeer method



	#--------------------------------------------------------------------------
	def __runstabilizer( self, stabilizer, delay ):
	#--------------------------------------------------------------------------
		while not self.shutdown:
			stabilizer()
			time.sleep( delay )



	#--------------------------------------------------------------------------
	def setmyid( self, myid ):
	#--------------------------------------------------------------------------
		self.myid = myid



	#--------------------------------------------------------------------------
	def startstabilizer( self, stabilizer, delay ):
	#--------------------------------------------------------------------------
		# """ Registers and starts a stabilizer function with this peer.
		# The function will be activated every <delay> seconds.
		#
		# """
		t = threading.Thread( target = self.__runstabilizer,
					  args = [ stabilizer, delay ] )
		t.start()



	#--------------------------------------------------------------------------
	def addhandler( self, msgtype, handler ):
	#--------------------------------------------------------------------------
		# """ Registers the handler for the given message type with this peer """
		assert len(msgtype) == 4
		self.handlers[ msgtype ] = handler



	#--------------------------------------------------------------------------
	def addrouter( self, router ):
	#--------------------------------------------------------------------------
		# """ Registers a routing function with this peer. The setup of routing
		# is as follows: This peer maintains a list of other known peers
		# (in self.peers). The routing function should take the name of
		# a peer (which may not necessarily be present in self.peers)
		# and decide which of the known peers a message should be routed
		# to next in order to (hopefully) reach the desired peer. The router
		# function should return a tuple of three values: (next-peer-id, host,
		# port). If the message cannot be routed, the next-peer-id should be
		# None.
		#
		# """
		self.router = router



	#--------------------------------------------------------------------------
	def addpeer( self, peerid, host, port ):
	#--------------------------------------------------------------------------
		# """ Adds a peer name and host:port mapping to the known list of peers.
		#
		# """
		if peerid not in self.peers and (self.maxpeers == 0 or
						 len(self.peers) < self.maxpeers):
			self.peers[ peerid ] = (host, int(port))
			self.__debug("Added peer %s: %s:%d"%(peerid,host,port))
			return True
		else:
			return False



	#--------------------------------------------------------------------------
	def getpeer( self, peerid ):
	#--------------------------------------------------------------------------
		# """ Returns the (host, port) tuple for the given peer name """
		assert peerid in self.peers    # maybe make this just a return NULL?
		return self.peers[ peerid ]



	#--------------------------------------------------------------------------
	def removepeer( self, peerid ):
	#--------------------------------------------------------------------------
		# """ Removes peer information from the known list of peers. """
		if peerid in self.peers:
			del self.peers[ peerid ]



	#--------------------------------------------------------------------------
	def addpeerat( self, loc, peerid, host, port ):
	#--------------------------------------------------------------------------
		# """ Inserts a peer's information at a specific position in the
		# list of peers. The functions addpeerat, getpeerat, and removepeerat
		# should not be used concurrently with addpeer, getpeer, and/or
		# removepeer.
		#
		# """
		self.peers[ loc ] = (peerid, host, int(port))



	#--------------------------------------------------------------------------
	def getpeerat( self, loc ):
	#--------------------------------------------------------------------------
		if loc not in self.peers:
			return None
		return self.peers[ loc ]



	#--------------------------------------------------------------------------
	def removepeerat( self, loc ):
	#--------------------------------------------------------------------------
		removepeer( self, loc )



	#--------------------------------------------------------------------------
	def getpeerids( self ):
	#--------------------------------------------------------------------------
		# """ Return a list of all known peer id's. """
		return self.peers.keys()



	#--------------------------------------------------------------------------
	def numberofpeers( self ):
	#--------------------------------------------------------------------------
		# """ Return the number of known peer's. """
		return len(self.peers)



	#--------------------------------------------------------------------------
	def maxpeersreached( self ):
	#--------------------------------------------------------------------------
		# """ Returns whether the maximum limit of names has been added to the
		# list of known peers. Always returns True if maxpeers is set to
		# 0.
		#
		# """
		assert self.maxpeers == 0 or len(self.peers) <= self.maxpeers
		return self.maxpeers > 0 and len(self.peers) == self.maxpeers



	#--------------------------------------------------------------------------
	def makeserversocket( self, port, backlog=5 ):
	#--------------------------------------------------------------------------
		# """ Constructs and prepares a server socket listening on the given
		# port.
		#
		# """
		s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
		s.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
		s.bind( ( '', port ) )
		s.listen( backlog )
		return s



	#--------------------------------------------------------------------------
	def sendtopeer( self, peerid, msgtype, msgdata, waitreply=True ):
	#--------------------------------------------------------------------------
		# """
		# sendtopeer( peer id, message type, message data, wait for a reply )
		#  -> [ ( reply type, reply data ), ... ]
		#
		# Send a message to the identified peer. In order to decide how to
		# send the message, the router handler for this peer will be called.
		# If no router function has been registered, it will not work. The
		# router function should provide the next immediate peer to whom the
		# message should be forwarded. The peer's reply, if it is expected,
		# will be returned.
		#
		# Returns None if the message could not be routed.
		# """

		if self.router:
			nextpid, host, port = self.router( peerid )
		if not self.router or not nextpid:
			self.__debug( 'Unable to route %s to %s' % (msgtype, peerid) )
			return None
		#host,port = self.peers[nextpid]
		return self.connectandsend( host, port, msgtype, msgdata,
						pid=nextpid,
						waitreply=waitreply )



	#--------------------------------------------------------------------------
	def connectandsend( self, host, port, msgtype, msgdata,
			pid=None, waitreply=True ):
	#--------------------------------------------------------------------------
		# """
		# connectandsend( host, port, message type, message data, peer id,
		# wait for a reply ) -> [ ( reply type, reply data ), ... ]
		#
		# Connects and sends a message to the specified host:port. The host's
		# reply, if expected, will be returned as a list of tuples.
		#
		# """
		msgreply = []
		try:
			peerconn = BTPeerConnection( pid, host, port, debug=self.debug )
			peerconn.senddata( msgtype, msgdata )
			self.__debug( 'Sent %s: %s' % (pid, msgtype) )

			if waitreply:
				onereply = peerconn.recvdata()
				while (onereply != (None,None)):
					msgreply.append( onereply )
					self.__debug( 'Got reply %s: %s'
						  % ( pid, str(msgreply) ) )
					onereply = peerconn.recvdata()
			peerconn.close()
		except KeyboardInterrupt:
			raise
		except:
			if self.debug:
				traceback.print_exc()

		return msgreply

		# end connectsend method



	#--------------------------------------------------------------------------
	def checklivepeers( self ):
	#--------------------------------------------------------------------------
		# """ Attempts to ping all currently known peers in order to ensure that
		# they are still active. Removes any from the peer list that do
		# not reply. This function can be used as a simple stabilizer.
		#
		# """
		todelete = []
		for pid in self.peers:
			isconnected = False
			try:
				self.__debug( 'Check live %s' % pid )
				host,port = self.peers[pid]
				peerconn = BTPeerConnection( pid, host, port, debug=self.debug )
				peerconn.senddata( 'PING', '' )
				isconnected = True
			except:
				todelete.append( pid )
				if isconnected:
					peerconn.close()

		self.peerlock.acquire()
		try:
			for pid in todelete:
				if pid in self.peers: del self.peers[pid]
		finally:
			self.peerlock.release()
		# end checklivepeers method



	#--------------------------------------------------------------------------
	def mainloop( self ):
	#--------------------------------------------------------------------------
		s = self.makeserversocket( self.serverport )
		s.settimeout(2)
		self.__debug( 'Server started: %s (%s:%d)'
				  % ( self.myid, self.serverhost, self.serverport ) )

		while not self.shutdown:
			try:
				self.__debug( 'Listening for connections...' )
				clientsock, clientaddr = s.accept()
				clientsock.settimeout(None)

				t = threading.Thread( target = self.__handlepeer,
							  args = [ clientsock ] )
				t.start()
			except KeyboardInterrupt:
				print('KeyboardInterrupt: stopping mainloop')
				self.shutdown = True
				continue
			except socket.timeout:
				continue
			except:
				if self.debug:
					traceback.print_exc()
					continue

		# end while loop
		self.__debug( 'Main loop exiting' )

		s.close()

	# end mainloop method

# end BTPeer class




# **********************************************************




class BTPeerConnection:

	#--------------------------------------------------------------------------
	def __init__( self, peerid, host, port, sock=None, debug=True ):
	#--------------------------------------------------------------------------
		# any exceptions thrown upwards

		self.id = peerid
		#self.debug = debug
		self.debug = True

		if not sock:
			self.s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
			self.s.connect( ( host, int(port) ) )
		else:
			self.s = sock

		self.sd = self.s.makefile( 'rwb', 0 )


	#--------------------------------------------------------------------------
	def __makemsg( self, msgtype, msgdata ):
	#--------------------------------------------------------------------------
		msglen = len(msgdata)
		msg = struct.pack( "!4sL%ds" % msglen, msgtype.encode(), msglen, msgdata )
		return msg


	#--------------------------------------------------------------------------
	def __debug( self, msg ):
	#--------------------------------------------------------------------------
		if self.debug:
			btdebug( msg )


	#--------------------------------------------------------------------------
	def senddata( self, msgtype, msgdata ):
	#--------------------------------------------------------------------------
		# """
		# senddata( message type, message data ) -> boolean status
		#
		# Send a message through a peer connection. Returns True on success
		# or False if there was an error.
		# """

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
		# """
		# recvdata() -> (msgtype, msgdata)
		#
		# Receive a message from a peer connection. Returns (None, None)
		# if there was any error.
		# """

		try:
			msgtype = self.sd.read( 4 )
			if not msgtype: return (None, None)

			lenstr = self.sd.read( 4 )
			msglen = int(struct.unpack( "!L", lenstr )[0])
			msg = b''

			while len(msg) != msglen:
				data = self.sd.read( min(2048, msglen - len(msg)) )
				if not len(data):
					break
				msg += data
			#if len(msg) != msglen:
			#	return (None, None)
			return ( msgtype.decode(), msg )
		except KeyboardInterrupt:
			raise
		except:
			if self.debug:
				traceback.print_exc()
		return (None, None)



		# end recvdata method


	#--------------------------------------------------------------------------
	def close( self ):
	#--------------------------------------------------------------------------
		# """
		# close()
		#
		# Close the peer connection. The send and recv methods will not work
		# after this call.
		# """

		self.s.close()
		self.s = None
		self.sd = None


	#--------------------------------------------------------------------------
	def __str__( self ):
	#--------------------------------------------------------------------------
		return "|%s|" % peerid
