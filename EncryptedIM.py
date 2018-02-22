'''
Nivu Jejurikar

This is an encrypted peer to peer chat program that allows a server and client
to send messages to each other continuously. The user inputs the hostname and  
two keys to run the program. Then an instance of either the client or server program is called 

The program is encrypted using AES-256 in CBC mode, and uses HMAC with SHA-246
for message authentication. This program uses a MAC-then-encrypt scheme.

'''

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Hash import MD5
from Crypto.Util.strxor import strxor
from Crypto import Random
import hashlib
import base64
import os
import argparse
import select
import socket
import sys
import signal
import select

IV = Random.new().read(AES.block_size)

#use mutually exclusive group so that usr may either choose 
#client or server mode, but not both. accept hostname as an argument
#accept the confidentiality (k1) and authenticity keys (k2) as arguments 
parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument("--s", action = "store_true")
group.add_argument("--c", help = "enter client mode after server mode initiated")
parser.add_argument("FOOBAR", help = "confidentiality key - key 1")
parser.add_argument("COSC235ISAWESOME", help = "authenticity key - key 2")


args = parser.parse_args()

global serverSocket
global clientSocket

#create confidentiality key used for encryption 
h1 = SHA256.new()
#this is the key below
h1.update('FOOBAR')
#hashed key 
hashkey1 = h1.digest() 

#create authenticity key used to generate HMAC
h2 = SHA256.new()
#this is the key below
h2.update('COSC235ISAWESOME')
#this is the hashed key 
hashkey2 = h2.digest() 


def createHMAC(hashkey2):
	#the secret shared key, K2, goes inside the HMAC function
	h = HMAC.new(hashkey2, 'Hello', digestmod=SHA256)
	h.update('Hello')
	return h.digest()

def AESEncryptor(hashkey1, message, IV):
	#encryptor takes in the k1 and encrypts in CBC mode using the IV
	#print message
	cipher = AES.new(hashkey1, AES.MODE_CBC, IV)
	ciphertext = cipher.encrypt(message)
	return ciphertext

def handler(signum, frame):
	#handler exits the program 
	clientSocket.close()
	sys.exit(0)

def AESDecryptor(hashkey1, ciphertext, IV):
	#decryptor takes in k1 and decrypts in CBC mode using the IV
	obj2 = AES.new(hashkey1, AES.MODE_CBC, IV)
	decrypted = obj2.decrypt(ciphertext)
	return decrypted

#call server code or client code depending on usr input

if args.s:
	#if usr chooses server mode, establish socket connection 
	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	host = ""
	port = 9999
	null = ""
	serverSocket.bind((host, port))

	#This program is set up to listen to up to 5 clients
	#accept the connection using the socket object and address inputted
	serverSocket.listen(5)
	serverSocket, addr = serverSocket.accept()
	#send the IV to the client 
	serverSocket.send(IV)


	signal.signal(signal.SIGINT, handler)
	while True:
		read_list = [serverSocket, sys.stdin]
		read_socket, write_socket, error_socket = select.select(read_list, [], [])
		#use select to manage incoming input inside first if statement, and 
		#output to server in elif statement
		for sock in read_socket:
			if sock == serverSocket:
				#receive input from client and then decrypt
				#verify if the MAC computed matches the one concatonated to the msg
				#if received address matches the actual, print the msg
				#if not print an error
				actualMac = createHMAC(hashkey2)
				lenMac = len(actualMac)
				ciphertext = serverSocket.recv(2048)
				decrypted = AESDecryptor(hashkey1, ciphertext, IV)
				recvMac = decrypted[-32:]
				

				if actualMac == recvMac:
					decryptFormat = decrypted.split('\n', 1) [0]
					sys.stdout.write(decryptFormat)
					sys.stdout.flush()
				else:
					print ("authentication failed - HMAC values do NOT match. Exiting program now.")
					handler()
				
				if ciphertext == null:
					serverSocket.close()
					break
			elif sock == sys.stdin:
				#accept std line input and add random value until the 
				#number of characters in the message is divisible by 16
				#concatenate the MAC, then encrypt and send to client
				msg = sys.stdin.readline()
				length = len(msg)
				random = os.urandom(length)
				secondlength = 16-(len(msg) % 16)
				secondrandom = os.urandom(secondlength)
				msg += secondrandom

				concat = createHMAC(hashkey2)
				msg += concat
				ciphertext = AESEncryptor(hashkey1, msg, IV)
				serverSocket.send(ciphertext)
				sys.stdout.flush()
			else:
				print("NOT std input or serversocket\n")


elif args.c:
	#connect to server, then receive the IV from server
	clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	host = socket.gethostname()
	clientSocket.connect((host, 9999))
	null = ""
	IV = clientSocket.recv(1024)

	signal.signal(signal.SIGINT, handler)
	while True:
		read_list = [sys.stdin, clientSocket]
		read_socket, write_socket, error_socket = select.select(read_list, [], [])
		for socks in read_socket:
			if socks == clientSocket:
				actualMac = createHMAC(hashkey2)
				lenMac = len(actualMac)
				ciphertext = clientSocket.recv(2048)
				decrypted = AESDecryptor(hashkey1, ciphertext, IV)
				recvMac = decrypted[-32:]
				if actualMac == recvMac:
					decryptFormat = decrypted.split('\n', 1) [0]
					sys.stdout.write(decryptFormat)
					sys.stdout.flush()
				else:
					print ("authentication failed - HMAC values do NOT match. Exiting program now.")
					handler()

				if ciphertext == null:
					clientSocket.close()
					break
			elif socks == sys.stdin:
				user_message = sys.stdin.readline()
				length = len(user_message)
				random = os.urandom(length)
				secondlength = 16-(len(user_message) % 16)
				secondrandom = os.urandom(secondlength)
				user_message += secondrandom

				concat = createHMAC(hashkey2)

				user_message += concat

				ciphertext = AESEncryptor(hashkey1, user_message, IV)
				clientSocket.send(ciphertext)
				sys.stdout.flush()
			else:
				print("NOT std input or serversocket\n")






