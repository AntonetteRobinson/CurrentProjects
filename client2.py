# Client to implement a simple program that will carry out an exchange of
# messages that implements a toy Diffie-Hellman key exchange protocol.
# The client sends a hello message to the server. The server responds
# with a message containing a generator and a prime.
# The client will respond with a message that contains an integer, which is
# the client's public key that is based on the generator and prime.
# The server responds to the client's public key message by sending the
# client its public key. The server, immediately follows this message by
# sending the client a nonce, which is a random number used once. The client
# transforms this nonce by subtracting 5 and then returns this integer to the
# server. The server confirms that the number that it received is 5 less than
# what was sent to client. 

# Author: fokumdt
# Last modified: 2025-09-21
#!/usr/bin/python3

import socket
import sys
import random
import re
import math
from random import SystemRandom
from NumTheory import NumTheory



#establish connection between client ad server



def serverHello():
  """Generates server hello message"""
  status = "100 Hello"
  return status

def computeSecretKey(g, p):
	"""Computes this node's secret key"""
	secretKey = random.randint(int(1), int(p))
	return secretKey

def computePublicKey(g, p, s):
	"""Computes a node's public key"""
	return NumTheory.expMod(g,s,p)

def sendPublicKey(g, p, s):
	"""Sends node's public key"""
	status = "120 PubKey " + str(computePublicKey(g, p, s))
	return status

# s     = socket
# msg   = message being processed
# state = dictionary containing state variables
def processMsgs(s, msg, state):
  """This function processes messages that are read through the socket. It
     returns a status, which is an integer indicating whether the operation
     was successful."""
  
  g,p,x,r = state["g"], state["p"], state["x"], state["r"],
   
  #process first message from server- generator

  if msg.startswith ("105"):
       #compute secret key 
       
       msg_break= msg.split()
       g = int(msg_break[-2].strip(","))
       p = int(msg_break[-1].strip(","))   
       state["p"]= p
       print("Values of G and P Sent by Server:" ,g, p)
       x= computeSecretKey(g,p)
       

       clientPublicKey= computePublicKey(g,p,x)
       print("publickey:" ,clientPublicKey)
     
       print("clientprivatekey: ", x)  
       state["x"]= x
       
       s.sendall(sendPublicKey(g,p,x).encode()) 
       return 0



  elif  msg.startswith("121"):
       
       msg2_break= msg.split()
       serverPublicKey = int(msg2_break[-1].strip(","))
       
       print("Server Public Key: ",serverPublicKey)

       sharedKey = NumTheory.expMod(serverPublicKey,state["x"],p )#state["x"]
       print("Shared Key: " + str(sharedKey))
       

       #with the client public key the shared key can be generated
     #to get shared key b=clientpublic key, n= server'pirvate key, p= prime
       
      
       return 0
  

  elif msg.startswith ("130"):
        msg3_break = msg.split()
        r= int(msg3_break[-1])
        print("nonce=", r)
     

        # compute transformed nonce
        trns_nonce =  r - 5
        print("trns:", trns_nonce)
        trns_message = ("131 Transformed nonce "+ str(trns_nonce) )
        s.sendall (trns_message.encode())


        
        return 0
    

  elif msg.startswith ("220"):
       print(msg)
       return 0
  

  elif msg.startswith("400"):
       print(msg)
       return 0 

  else:
       print("Excecution error")
       sys.exit(1) 

  return state 

def main():
  """Driver function for the project"""
  args = sys.argv
  if len(args) != 3:
    print("Please supply a server address and port.")
    sys.exit()
  serverHost = str(args[1])  #The remote host
  serverPort = int(args[2])  #The port used by the server
  print("Client of Antonette Robinson")
  


  #Add code to initialize the socket
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
       clientSocket.connect((serverHost,serverPort))
       
  #Add code to send data into the socket
    
       msg = serverHello()
       clientSocket.sendall(msg.encode())
          
       state = {"p": None, "g": None, "x": None, "r": None}

       while True:

        msg = clientSocket.recv(1024).decode()
    
        if not msg:
            print("closed connection")
            break
        processMsgs(clientSocket, msg, state)

        if msg.startswith("220"):
          print("Handshake Completed")
          break  # exit loop after successful handshake
        elif msg.startswith("400"):
          print("Handshake Error")
          break  # exit loop on error
   
       clientSocket.close()   
       
 
    
if __name__ == "__main__":
    main()
  