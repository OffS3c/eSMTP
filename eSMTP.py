#!/usr/bin/python

from __future__ import print_function
from prettytable import PrettyTable
from threading import Thread
from itertools import takewhile, repeat

import sys, argparse, socket, os, threading, time, linecache



class CheckSmtpHost(Thread):
	
	__threadID      = None
	__users         = None
	__results       = []
	__completed     = False
	__timeout       = None
	__socket        = None
	__haveResults   = False
	__lockResults   = False


	def __init__(self, threadID, ip, users, timeout, socket) :
		super(CheckSmtpHost, self).__init__()
		self.__threadID = threadID
		self.__ip = ip
		self.__users = users
		self.__completed = False
		self.__timeout = timeout
		self.__socket = socket
		self.__haveResults = False
		self.__lockResults = False


	def __addInList(self, item) : 
		self.__haveResults = True
		while self.__lockResults :
			self.__usleep(100) # can be a deadlock if you don't free the resource 
		self.__lockResults = True
		self.__results.append(item)
		self.__lockResults = False

	def __usleep(self, microseconds) :
		time.sleep(microseconds/1000000.0)

	def getThreadID(self) :
		return self.__threadID

	def getResults(self) :
		while self.__lockResults :
			self.__usleep(100) # can be a deadlock if you don't free the resource 
		self.__lockResults = True
		
		results = list(self.__results)
		#printer("Clearing results\n", "d")
		for result in results : 
			self.__results.remove(result)
		self.__haveResults = False
		#printer("Cleared results\n", "d")

		self.__lockResults = False

		return results

	def isComplete(self) :
		if (not self.__haveResults and self.__completed) :
			return True
		else :
			return False

	def run(self) :
		host = self.__ip
		printer("Thread ID: " + str(self.getThreadID()) + " Thread against " + host + " starting...\n", "d")
		printer("Thread ID: " + str(self.getThreadID()) + " Connecting to " + host + "\n", "d")
		conn = None
		try :
			conn = SMTP(host, timeout=self.__timeout).connectServer(self.__socket)
			printer("Thread ID: " + str(self.getThreadID()) + " Connected to " + host + "\n", "d")
		except :
			conn = None
			printer("Thread ID: " + str(self.getThreadID()) + " Connection to " + host + " failed!\n", "d")
		test = conn.testConnection()
		if test is False :
			printer("Thread ID: " + str(self.getThreadID()) + " Test failed for " + host + "\n", "d")
		else : 
			printer("Thread ID: " + str(self.getThreadID()) + " Test completed for " + host + "\n", "d")
		printer("Thread ID: " + str(self.getThreadID()) + " Saying hello to " + host + "\n", "d")
		conn.sayHello()
		printer("Thread ID: " + str(self.getThreadID()) + " Said hello to " + host + "\n", "d")
		printer("Thread ID: " + str(self.getThreadID()) + " Fingerprinting OS against " + host + "\n", "d")
		isWin = conn.isWindows()
		printer("Thread ID: " + str(self.getThreadID()) + " Fingerprinted OS against " + host + "\n", "d")

		for usr in self.__users :
			printer("Thread ID: " + str(self.getThreadID()) + " Testing User " + usr + " against " + host + "\n", "d")
			usrExists = conn.userExists(usr)
			printer("Thread ID: " + str(self.getThreadID()) + " Tested User " + usr + " against " + host + "\n", "d")

			printer("Thread ID: " + str(self.getThreadID()) + " Adding result\n", "d")
			self.__addInList([host, test, isWin, usr, usrExists])
			printer("Thread ID: " + str(self.getThreadID()) + " Added result\n", "d")

		printer("Thread ID: " + str(self.getThreadID()) + " Disonnecting from " + host + "\n", "d")
		conn.disconnectServer()
		printer("Thread ID: " + str(self.getThreadID()) + " Disonnected from " + host + "\n", "d")
		self.__haveResults = True
		self.__usleep(150000) 
		self.__completed = True
		printer("Thread ID: " + str(self.getThreadID()) + " Thread against " + host + " finished!\n", "d")

########################################
# SMTP class

class SMTP(object): # TODO : add ISA Server email spoof testing
	
	"""SMTP wrapper"""
	__banner       = None
	__ip           = None
	__port         = None
	__timeout      = None
	__connection   = None
	

	def __init__(self, ip, port=25, timeout=30) :
		super(SMTP, self).__init__()
		self.__ip = ip
		self.__port = port
		self.__timeout = timeout
		
			
	def connectServer(self, socket) :
		try :
			try:
				socket.inet_aton(self.__ip)
			except socket.error:
				printer("Invalid IP: " + self.__ip + "\n", "n")
				return self
			clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			clientSocket.settimeout(self.__timeout)
			clientSocket.connect((self.__ip, self.__port))
			self.__connection = clientSocket
			try : 
				self.__banner = self.__connection.recv(1024)
			except : 
				self.__banner = None
		except :
			self.__connection = None
		return self


	def disconnectServer(self) : #clean disconnect :)
		if self.isConnected() :
			response = self.__QUIT()
			resCode  = self.__getResponseCode(response)
			if resCode == "221" :
				self.__connection.close()
				return True
			else :
				return False
		else :
			return False
		

	def __getResponse(self, command) :
		printer("Sending command " + command + " to " + self.__ip + "\n", "d")
		self.__connection.settimeout(self.__timeout)

		try : 
			self.__connection.send(command + "\r\n")
			printer("Sent command " + command + " to " + self.__ip + "\n", "d")
		except :
			printer("Failed to send command to " + self.__ip + ". Timeout occoured.\n", "d")
			return "000 ERROR"

		printer("Receiving response from " + self.__ip + "...\n", "d")
		
		try : 
			response = ""
			
			'''
			while True :
				self.__connection.settimeout(self.__timeout)
				printer("Receiving chunk from " + self.__ip + "\n", "d")
				try :
					chunk = self.__connection.recv(65536)
					printer("Received chunk (" + str(len(chunk)) + ") from " + self.__ip + ": " + chunk + "\n", "d")
				except :
					chunk = ""

				if len(chunk) == 0 :
					break
				else :
					response += chunk

			'''
			response = self.__connection.recv(65536)
			smtpResponse = response

			printer("Received response from " + self.__ip + ": " + smtpResponse + "\n", "d")
			return smtpResponse
		except :
			printer("Failed to receive response from " + self.__ip + ". Timeout occoured.\n", "d")
			return "000 ERROR"
		

	def __getResponseCode(self, smtpResponse) :
		return smtpResponse.split(' ')[0]

	def __getResponseInfo(self, smtpResponse) :
		return smtpResponse.split(' ', 1)[1]
	


	def __NOOP(self) :
		return self.__getResponse("NOOP domain.local")

	def __HELO(self) :
		return self.__getResponse("HELO domain.local")

	def __HELP(self) :
		try :
			return self.__getResponse("HELP domain.local").split('\n')[1]
		except :
			return self.__getResponse("HELP domain.local")

	def __EHLO(self) :
		return self.__getResponse("EHLO domain.local")

	def __QUIT(self) :
		#return self.__getResponse("QUIT domain.local")
		return self.__getResponse("QUIT")

	def __RSET(self) :
		return self.__getResponse("RSET domain.local")

	def __VRFY(self, username) :
		#return self.__getResponse("VRFY " + username + " domain.local")
		return self.__getResponse("VRFY " + username)


	def isConnected(self) :
		if self.__connection is not None:
			return True
		else :
			return False

	def getBanner(self) :
		if self.isConnected() : 
			resCode  = self.__getResponseCode(self.__banner)
			if resCode == "214" :
				return self.__getResponseInfo(self.__banner)
				#return True
			else :
				return False
		else :
			return False

	def testConnection(self) :
		if self.isConnected() :
			response = self.__NOOP()
			resCode  = self.__getResponseCode(response)
			if resCode == "250":
				return True

		self.__connection = None
		return False

	def userExists(self, username) :
		if self.isConnected() :
			response = self.__VRFY(username)
			resCode  = self.__getResponseCode(response)
			if resCode == "250" :
				return True
			else :
				return False
		else :
			return False

	def isWindows(self) :
		if self.isConnected() :
			response = self.__EHLO()
			if "ntlm" in response.lower().split() :
				return True
			else :
				return False
		else :
			return False

	def sayHello(self) :
		if self.isConnected() :
			response = self.__HELO()
			resCode  = self.__getResponseCode(response)
			if resCode == "250" :
				return True
			else :
				return False
		else :
			return False

	def resetConnection(self) :
		if self.isConnected() :
			response = self.__RSET()
			resCode  = self.__getResponseCode(response)
			if resCode == "250" :
				return True
			else :
				return False
		else :
			return False

	def askForHelp(self) :
		if self.isConnected() :
			response = self.__HELP()
			resCode  = self.__getResponseCode(response)
			if resCode == "214" :
				return self.__getResponseInfo(response)
				#return True
			else :
				return False
		else :
			return False


########################################


########################################
# print methods

def clearScreen():
    os.system('cls' if os.name=='nt' else 'clear')

def printer(msg, type="") :
	if type == "p" : #positive
		print ("[+] " + msg, end='')
	elif type == "n" : #negative
		print ("[-] " + msg, end='')
	elif type == "i" : #info
		print ("[i] " + msg, end='')
	elif type == "d" : #debug
		if args.debug :
			print ("[DEBUG] " + msg, end='')
	elif type == "t" : #table
		if not args.debug :
			clearScreen()
			print (msg, end='\n')
	else :
		print (msg, end='')


def makeTable(resultArr) :
	sortedArr = sorted(resultArr, key=lambda x: x[0], reverse=True)
	table = PrettyTable(["Host", "Connection", "Is Windows", "User", "User Exists"])
	
	for indx in sortedArr:
		Host        = indx[0]
		Connection  = indx[1]
		Type        = indx[2]
		User        = indx[3]
		UserExists  = indx[4]

		if Connection is True :
			Connection = "Successful"
		else :
			Connection = "Failed"

		if Type is True :
			Type = "Yes"
		else :
			Type = "Maybe"

		if UserExists is True :
			UserExists = "Yes"
		else :
			UserExists = "No"

		table.add_row([Host, Connection, Type, User, UserExists])

	return table
	
########################################



def getNumLines(filename) :
    return sum([1 for i in open(filename,"r").readlines() if i.strip()])


def readBetweenLines(filename, startingLine, endingLine) : 
	lines = []
	for i in xrange(startingLine, endingLine) :
		line = linecache.getline(filename, i)
		if line.strip() :
			lines.append(line.replace('\n', ''))
	return lines


def getArgs() :
	parser = argparse.ArgumentParser(description='You need to provide some arguments for me to work')
	parser.add_argument("-b", "--banner", help="don't print banner", action="store_true")
	parser.add_argument("-U", "--users", help="path to the file containing target user(s) to test")
	parser.add_argument("-u", "--user", help="target user to test")
	parser.add_argument("-T", "--targets", help="path to the file containing target IP(s) to test")
	parser.add_argument("-t", "--target", help="target user to test")
	parser.add_argument("--threads", help="threads or max connections at a time ( Default:1, Max:50 ) ")
	parser.add_argument("--timeout", help="connection timeout in seconds ( Default:30, Max:240 ) ")
	#parser.add_argument("-N", "--report-name", help="creates a directory in which all report files are present for the current session")
	parser.add_argument("-d", "--debug", help="be very very verbose", action="store_true")

	args = parser.parse_args()
	return args



def refreshScreen():
	global results

	threading.Timer(2.0, refreshScreen).start()
	table = makeTable(results)
	printer(table, "t")


def produceResults(hosts, users) :
	global THREADS, threads, results

	numOfThreads = 0
	numOfRunningThreads = 0

	if THREADS > len(hosts) :
		THREADS = len(hosts)
		printer("thread count set to " + str(THREADS) + " due to less hosts\n", "d")

	totalResults = 0

	for host in hosts:
		numOfThreads += 1
		thrdID = numOfThreads
		thrd = CheckSmtpHost(thrdID, host, users, TIMEOUT, socket)
		thrd.daemon = True
		thrd.start()
		#printer("= TID START: " + str(thrd.getThreadID()) + " =\n", "d")
		numOfRunningThreads += 1
		threads.append(thrd)
		
		while True :
			time.sleep(0.5)
			if len(threads) >= THREADS :
				for thred in threads[:] :
					#printer("Getting results\n", "d")
					result = thred.getResults()
					#printer("Got " + len(result) + " results\n", "d")
					if len(result) is not 0 :
						printer("Got " + str(len(result)) + " result(s)\n", "d")
						totalResults += len(result)
						results += result
					else : 
						if thred.isComplete() :
							#printer("= TID END: " + str(thred.getThreadID()) + " =\n", "d")
							threads.remove(thred)
							numOfRunningThreads -= 1
							thred.join()

			if numOfRunningThreads < THREADS :
				printer("Trying to reallocate thread resource if all jobs are not done\n", "d")
				break

			else : 
				break

	# collect remaining results :) 
	printer("Collecting remaining results\n", "d")
	while numOfRunningThreads is not 0 :
		time.sleep(0.5)
		for thred in threads[:] :
			#printer("Getting results\n", "d")
			result = thred.getResults()
			#printer("Got " + len(result) + " results\n", "d")
			if len(result) is not 0 :
				printer("Got " + str(len(result)) + " result(s)\n", "d")
				totalResults += len(result)
				results += result
			else : 
				if thred.isComplete() :
					#printer("= TID END: " + str(thred.getThreadID()) + " =\n", "d")
					threads.remove(thred)
					numOfRunningThreads -= 1
					thred.join()



def exitProgram(code) :
	global results, args

	table = makeTable(results)
	
	if args.debug :
		print("")
		print(table)
	else :
		if code is 0 :
			printer(table, "t")
		else :
			print("")
			print(table)

	os._exit(code)


def validateArgs() :

	global TIMEOUT, THREADS, args, host, user

	if not args.banner :		
		printer("\n[!] eSMTP   : A multithreadded tool to enumerate SMTP User/OS information from SMTP Servers (version 1.0b)\n")
		printer("[A] Author  : OffS3c (https://offs3c.com) \n")
		printer("[C] Company : Glaxosoft (https://glaxosoft.com) \n\n")


	if not (args.targets or args.target):
		printer("atleast 1 target is required\n", "n")
		exitProgram(1)

	if not (args.users or args.user):
		printer("atleast 1 user is required\n", "n")
		exitProgram(1)

	if (args.targets and args.target):
		printer("please use -t OR -T \n", "n")
		exitProgram(1)

	if (args.users and args.user):
		printer("please use -u OR -U \n", "n")
		exitProgram(1)

	if args.timeout:
		if int(args.timeout) in xrange(1, 120) :
			printer("timeout set to " + args.timeout + " seconds\n", "d")
			TIMEOUT = int(args.timeout)
		else :
			printer("Invalid timeout value. Defaulting to 30 seconds\n", "n")

	if args.threads:
		if int(args.threads) in xrange(1, 50) :
			printer("thread count set to " + args.threads + "\n", "d")
			THREADS = int(args.threads)
		else :
			printer("Invalid thread count. Defaulting to 1\n", "n")


	if args.user :
		user = [args.user]

	if args.target : 
		host = [args.target]



def main() :
	global args, host, user, results, TIMEOUT, THREADS, threads

	validateArgs()
	refreshScreen()

	numOfHosts = 0
	hosts = None
	numOfUsers = 0
	users = None

	numOfHostFileParts = 0
	hostsSegmentsRead = 0
	usersSegmentsRead = 0
	numOfUserFileParts = 0
	
	if args.target :
		if args.user :
			produceResults(host, user)
		else :
			numOfUsers = getNumLines(args.users)
			numOfUserFileParts = int(numOfUsers/50)
			if ( (numOfUserFileParts*50) < numOfUsers ) :
						numOfUserFileParts += 1

			while not usersSegmentsRead == numOfUserFileParts : 
				startingLine = usersSegmentsRead * 50
				endingLine = startingLine + 50

				users = readBetweenLines(args.users, startingLine, endingLine)
				usersSegmentsRead += 1

				produceResults(host, users)
	
	else :
		
		numOfHosts = getNumLines(args.targets)
		numOfHostFileParts = int(numOfHosts/50)
		if ( (numOfHostFileParts*50) < numOfHosts ) :
					numOfHostFileParts += 1

		while not hostsSegmentsRead == numOfHostFileParts : 
			startingLine = hostsSegmentsRead * 50
			endingLine = startingLine + 50

			hosts = readBetweenLines(args.targets, startingLine, endingLine)
			hostsSegmentsRead += 1

			if args.user :
				produceResults(hosts, user)
			else :
				numOfUsers = getNumLines(args.users)
				numOfUserFileParts = int(numOfUsers/50)
				if ( (numOfUserFileParts*50) < numOfUsers ) :
							numOfUserFileParts += 1
	
				while not usersSegmentsRead == numOfUserFileParts : 
					startingLine = usersSegmentsRead * 50
					endingLine = startingLine + 50

					users = readBetweenLines(args.users, startingLine, endingLine)
					usersSegmentsRead += 1

					produceResults(hosts, users)
	

	exitProgram(0)


##########################################
TIMEOUT = 30
THREADS = 1
user = None
host = None
results = []
threads = []

args = getArgs()
##########################################




if __name__ == '__main__': 
	try:
		main()
	except KeyboardInterrupt:
		printer("Exiting...", "i")
        exitProgram(0)
