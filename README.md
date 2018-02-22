# Encrypted_ChatRoom
This is an encrypted peer to peer chat program that allows a server and client
to send messages to each other continuously. The user inputs the hostname and  
two keys to run the program. Then an instance of either the client or server program is called 

The program is encrypted using AES-256 in CBC mode, and uses HMAC with SHA-246
for message authentication. This program uses a MAC-then-encrypt scheme.
