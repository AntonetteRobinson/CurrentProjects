# Server to implement a simple program that will exchange messages to carry
# out a simplified Diffie-Hellman key exchange.
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
import hashlib
import time
from NumTheory import NumTheory

def PrimeCollect():
  """Accepts a prime number to send to the client"""
  primeNbr = int(input("Enter a prime number between 257 and 4093: "))
  return primeNbr
  

def GeneratorCollect():
  """Accepts a generator for the prime"""
  generator = int(input("Enter a generator for the prime number: "))
  return generator

def clientHello(g, p,x,r):
  """Generates an acknowledgement for the client's hello message"""
  msg = "105 Generator + Prime "+ str(g) + ", " + str(p)
  return msg

def computePublicKey(g, p, s):
	"""Computes a node's public key"""
	return NumTheory.expMod(g,p,s)

def computeSecretKey(g, p):
	"""Computes this node's secret key"""
	secretKey = random.randint(int(1), int(p))
	return secretKey
    
def sendPublicKey(g, p, s):
	"""Sends node's public key"""
	status = "121 PubKey " + str(computePublicKey(g, p, s))
	return status

def generateNonce():
	"""This method returns a 16-bit random integer derived from hashing the
		current time. This is used to test for liveness"""
	hash = hashlib.sha1()
	hash.update(str(time.time()).encode('utf-8'))
	return int.from_bytes(hash.digest()[:1], byteorder=sys.byteorder)


def AllGood():
  """Generates 220 Verified"""
  status = "220 Verified"
  return status

def ErrorCondition():
  """Generates 400 Error"""
  status = "400 Error"
  return status

#s      = socket
#msg    = message being processed
#state  = dictionary containing state variables

def processMsgs(conn, msg, state):
  """This function processes messages that are read through the socket. It returns
     a status, which is an integer indicating whether the operation was successful."""
  
  g,p,x,r = state["g"],state["p"],state["x"],state["r"]   
  
  if msg.startswith("100"):
      print("Client sends greetings:",msg)
      conn.sendall(clientHello(g,p,x,r).encode() ) #send message to client
      
      return 0
      
  elif msg.startswith("120"):
      client_publicKey_string =msg.split()
      clientPublicKey= int(client_publicKey_string[-1].strip(","))
      print(clientPublicKey)
      print("Client Public Key:" + str(clientPublicKey))
      conn.sendall(sendPublicKey(g,x,p).encode())  #server public key sent
      #using the public key from client compute shared key
      
      sharedKey = NumTheory.expMod(clientPublicKey,x,p)
      print("Shared Key :", sharedKey) 
      r =generateNonce()
      state["r"]=r
      print("nonce =", r)
      
      if  5 < r < p:
          sendNonce= ("130 Nonce " + str(r))
          print("sendnonce:", sendNonce)
          conn.sendall(sendNonce.encode())
      


     #to get shared key b=clientpublic key, n= server'pirvate key, p= prime
      print ("X=",x)
      # sharedKey = NumTheory.expMod(clientPublicKey,x, p)
      # print ("Shared Key: ", sharedKey)

      #share server public key to client
     
   
     #generate nonce
      
      return 0
      

  elif msg.startswith("131"):
      print(msg)
      break_msg=msg.split()
      transformed_nonce = int(break_msg[-1])
      print("t",transformed_nonce)
      
      
      print("original", state["r"])
      n= transformed_nonce - state["r"]
      print("transformed nonce - Original =" , n)
      if abs(n) == 5:
        conn.sendall(AllGood().encode())
      else:
        conn.sendall(ErrorCondition().encode())
      return 0
  else: 
      print( "Server Exeution error")
            
        


def main():
    """Driver function for the server."""
    args = sys.argv
    if len(args) != 2:
        print("Please supply a server port.")
        sys.exit()
    HOST = ''               # Symbolic name meaning all available interfaces
    PORT = int(args[1])     # The port on which the server is listening.
    if (PORT < 1023 or PORT > 65535):
        print("Invalid port specified.")
        sys.exit()

    print("Server of Antonette Robinson")

    # Collect input of p and g before starting the server
    while True:
        p = PrimeCollect()

        g = GeneratorCollect()
      

        # Check if p and g are valid
        if not NumTheory.IsPrime(p) or not NumTheory.IsValidGenerator(g, p):
            print("p and g do not satisfy requirements. Try again.")
        else:
            break

    # Server secret key
    x = computeSecretKey(g, p)
    print("Secret key:", x)

    # Server public key
    publicKey = computePublicKey(g, p, x)

    print("Public key:", publicKey)

    # Start listening on the socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server is listening on {HOST}:{PORT}")

        conn, addr = s.accept()  # accept connections using socket
        with conn:
            print("Connected from:", addr)

            # Start receiving messages
            state = {"p": p, "g": g, "x": x, "r": None}
            while True:
                msg = conn.recv(1024).decode()
                if not msg:
                    print("Connection closed by client.")
                    break
                processMsgs(conn, msg, state)

        conn.close()

if __name__ == "__main__":
    main()
