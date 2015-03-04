# Copyright (C) 2014 Ryan Haley
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Author:: Ryan Haley
# Copyright:: Copyright (c) 2014
# License:: GPLv2




#TO DO - support other mail records (mx, etc)
# DOS Protection
# Response for not found
# Zone transfer and cache
# Report zone transfer requests
# Multithreaded

import socket
from time import strftime
from subprocess import call
from os import name, system
myHost = "0.0.0.0"
myPort = 53



class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.domain=''
    self.listen()


  def listen(self):
    #Get domain name from packet  http://www.networksorcery.com/enp/protocol/dns.htm
    # import code
    # code.interact(local=locals())
    ptype = (ord(data[2]) >> 3) & 15   # Opcode bits
    if ptype == 0:                     # If 0 = Standard query (1 is answer)
      domain_location=12
      check=ord(data[domain_location])    
      while (check != 0):              #Check first byte for domain in request
        self.domain += data[domain_location+1:domain_location + check + 1] + '.' #Get each part of domain up to .
        domain_location += check+1
        check = ord(data[domain_location]) 
    length=len(self.domain)             #length of subset domain
    # if ord(data[-3])    WHY???
    #   pass
    if (length < 30) and "%" not in self.domain:  #LIMIT QUERY LENGTH & PREVENT % in QUERY (prevent long, uneeded requests)
      pass
    else:
      LOG = open(".dns.log", "a")
      message = "WARNING: INVALID REQUEST -- {}".format(self.domain)
      print message
      LOG.write(message)
      self.domain = ''
      LOG.close()
   

  def reply(self, ip):
    packet=''
    if self.domain:
      packet+=self.data[:2]                                          # Transaction ID
      packet+= "\x81\x80"                                            # Standard Query Respone, 1 Answer (Flags)
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
    return packet

  #FUTURE DEVELOPMENT - TODO
  # def send_records(self, ip):
  #   packet=''
  #   if self.domain:
  #     packet+=self.data[:2] + "\x81\x80"
  #     packet+=self.data[4:6] + self.data[4:6] + '\x00\x01\x00\x00'   # Questions and Answers Counts
  #     packet+=self.data[12:-4]                                         # Original Domain Name Question
  #     packet = len(packet)
  #   return packet

  # def get_records(self, ip):
  #   length = ord(data[0:2])                #length of remaining packet
  #   ord(data[5]) & 128                      # response type (should be 1)
  #   ord(data[26:28])                        # Number of records in respose
  #   data.index("fc")                        # Find query section 

def get_domains(namedict):
  domains = []
  ifile = raw_input("File: ")
  ifile = open(ifile,"r")
  tmp = ifile.read()
  tmp2 = tmp.split("\n")
  for each in tmp2:
    domains.append(each.split(" "))
  ifile.close()
  for each in domains:
    if each[0] != '':
      namedict[each[0]] = each[1]
  return namedict




if __name__ == '__main__':

  #Placeholder
  namedict = {      ###############CHANGE TEAM NUMBERS!?
  }

  # Add input file of domain/IP mappings to namedict
  namedict = get_domains(namedict)



  # Open UDP socket 
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.bind((myHost,myPort))
  SysType = name.lower()

  #set accurate secondary server
  try:
    if SysType == "posix" or SysType == "linux" or SysType == "unix":
      call("sed -i '1inameserver 8.8.8.8 /etc/resolv.conf", shell=True) 
      print "Linux Found, setting DNS to 8.8.8.8"
    else:
      system('netsh interface ip set dns "Local Area Connection" static 8.8.8.8')
      print "Windows Found, setting DNS to 8.8.8.8"
  except:
    print "Error changing local DNS Server"





  while True:
    LOG = open(".dns.log", "a")
    data, addr = s.recvfrom(150)
    if not data: break
    p = DNSQuery(data)
    
    # Lookup query in cache
    try:
      if p.domain[-1] == ".":
        tmp = p.domain[:-1]
      answer = namedict[tmp]

      if (answer):
        s.sendto(p.reply(answer),addr)
        print 'Reply: {} -- {} -> {}'.format(p.domain, answer, addr)
        LOG.write('Reply: {} -- {}\n{}\n{}\n\n'.format(p.domain, answer, addr,str(strftime("%I:%M:%S"))))

    # If not successful, lookup with secondary dns
    except:
        try:
          ip = socket.gethostbyname(p.domain)
          s.sendto(p.reply(ip),addr)
          print 'External Reply: {} -- {}\n'.format(p.domain, ip,)
          LOG.write('External Reply: {} -- {}\n{}\n\n'.format(p.domain, ip,str(strftime("%I:%M:%S"))))
        except: 
          print "WARNING Could not perform lookup {}".format(p.domain)
          LOG.write("WARNING Could not perform lookup {}\n{}\n\n".format(p.domain,str(strftime("%I:%M:%S"))))

    LOG.close()
        
