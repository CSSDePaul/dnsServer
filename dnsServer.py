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
#Test secondary DNS check
# Response for not found
# Implement DoS Protection

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
    #Get domain name from packet
    ptype = (ord(data[2]) >> 3) & 15   # Opcode bits
    if ptype == 0:                     # If 0 = Standard query (1 is answer)
      ini=12
      check=ord(data[ini])    
      while (check != 0):              #Check first byte for domain in request
        self.domain+=data[ini+1:ini+check+1]+'.' #Get each part of domain up to .
        ini+=check+1
        check=ord(data[ini]) #length of subset domain
    length=len(self.domain)
    if (length < 28) and "%" not in self.domain:  #LIMIT QUERY LENGTH & PREVENT % in QUERY
      pass
    else:
      LOG = open(".dns.log", "a")
      message = "WARNING: PACKET ERROR -- {}".format(self.domain)
      print message
      LOG.write(message)
      self.domain = ''
      LOG.close()
   
  def reply(self, ip):
    packet=''
    if self.domain:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
    return packet

if __name__ == '__main__':
  sn = raw_input("Root DNS:")
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.bind((myHost,myPort))
  SysType = name.lower()

  #set accurate secondary server
  try:
    if SysType == "posix" or SysType == "linux" or SysType == "unix":
      call("sed -i '1inameserver " + sn + "' /etc/resolv.conf", shell=True) 
      print "Linux Found, setting DNS to" + sn
    else:
      system('netsh interface ip set dns "Local Area Connection" static' + sn)
      print "Windows Found, setting DNS to" + sn
  except:
    print "Error changing local DNS Server"

  while True:
    LOG = open(".dns.log", "a")

    #Listen for query
    data, addr = s.recvfrom(100)
    if not data: break
    p = DNSQuery(data)
    
    try:
      ip = socket.gethostbyname(p.domain)
      s.sendto(p.reply(ip),addr)
      print '\nWARNING Reply: {} -- {}\n'.format(p.domain, ip,)
      LOG.write('Warning Reply: {} -- {}\n{}\n\n'.format(p.domain, ip,str(strftime("%I:%M:%S"))))
    except: 
      print "Error from request {}".format(p.domain)
      LOG.write("Error from request {}\n{}\n\n".format(p.domain,str(strftime("%I:%M:%S"))))

    LOG.close()
        
