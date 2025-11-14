#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# net.py
#
#

import os
import sys
import re
import shutil
from datetime import datetime
import signal
import socket
import ssl
import subprocess32 as subprocess
import time
from time import time as timer
from tqdm import tqdm
import threading

try:
    ConnectionRefusedError # py3
except NameError:
    ConnectionRefusedError = socket.error # py2

import core
import run
import debug
import triage
import misc
import config
import settings
from settings import SUCCESS, FAILURE

#
# local client / server fuzzing and crash replay for debugging
#
def main(cmdline):
    if(config.debug):
        print("entering net.main()\n")

    startTime = timer()

    #
    # setup TLS
    #
    if(config.tls):
        try:
            if((config.mode == settings.SERVER) or (config.mode == settings.LOCAL_SERVER)):
                config.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            else: # client
                config.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            config.context.check_hostname = False
            config.context.verify_mode = ssl.CERT_NONE
            config.context.load_cert_chain(settings.NETWORK_CRT, keyfile=settings.NETWORK_KEY)
        except Exception as error:
            print("\n[ERROR] net.main() @ SSL create context: %s\n" % error)
            return FAILURE

    if((config.mode == settings.CLIENT) or (config.mode == settings.LOCAL_CLIENT)):
        startServer(cmdline, False) # start built-in server to fuzz target client
    else:
        startClient(cmdline, False) # start built-in client to fuzz target server

    if(config.conn == None):
        print("\n[ERROR] net.main() @ socket: likely a timeout or SSL issue, try running it again\n")
        misc.killTargetProcesses()
        sys.exit(FAILURE)

    #
    # *now for the fun part*
    #
    # four scenarios which may be signs of a crash
    #
    # 1) we can't connect to the target anymore (previous mutant)
    # 2) we can connect, but cannot send data (previous mutant)
    # 3) we can send data, but recv zero bytes (current mutant)
    # 4) we can connect, but cannot send data AFTER sending data (current mutant)
    #

    #
    # crash scenario #1
    #
    # connect to target
    #
    # -> if connect fails, check for crash by repro'ing PREVIOUS fuzz file
    #
    if(config.mode == settings.SERVER or (config.mode == settings.LOCAL_SERVER)):
        try:
            config.conn.connect((config.host, config.port))
        except Exception as error:
            if(config.count == 1):
                if(config.mode == settings.LOCAL_SERVER):
                    if(config.debug):
                        print("[INFO] connection failed, giving the target a few more seconds to spin up\n")

                    time.sleep(settings.LOCAL_SERVER_TIMEOUT)

                try:
                    if(config.tls == False): # we're already connected if using TLS
                        config.conn.connect((config.host, config.port))
                except Exception as error:
                    print("\n[ERROR] net.main() @ connect: %s\n" % error)
                    misc.killTargetProcesses()
                    sys.exit(FAILURE)
            else:
                if(config.debug):
                    print("\n[INFO] failed to make a connection to target\n")

                if((config.mode == settings.CLIENT) or (config.mode == settings.SERVER)):
                    if((config.attach == None) and (config.report_crash == False)):
                        config.down = True # this var is too useful :')
                        misc.clientServerCrash()
                else:
                    if(misc.isUnix()):
                        if(core.reproCrash(settings.FUZZ_FILE_PREV, cmdline, False) != SUCCESS):
                            if(config.debug):
                                print("[INFO] couldn't repro crash @ initial connect\n")
                            return FAILURE
                        else:
                            return SUCCESS

    #
    # support connect() -> attaching to the process in a debugger
    #
    # note: this supports the general scenarion and also processes that launchd spawns
    #
    if(config.attach):
        time.sleep(1) # give it a second in case it's a parent process forking a child

        if(config.attach.isnumeric()):
            pid = config.attach

            if(config.debug):
                print("calling debug.attach() for pid=%s\n" % pid)
        else:
            pid = misc.processPid(config.attach)

            if(pid == None):
                print("[ERROR] net.main() @ attach failed for %s: couldn't get pid\n" % config.attach)
                misc.killTargetProcesses()
                sys.exit(FAILURE)

            if(config.debug):
                print("calling debug.attach() for name=%s pid=%s\n" % (config.attach, pid))

        debug.attach('lldb', pid)

    #
    # initial recv()
    #
    buf = None

    try:
        if(config.prot == 'tcp'):
            buf = config.conn.recv(settings.RECV_SIZE)
        else:
            (buf, address) = config.conn.recvfrom(settings.RECV_SIZE)
    except Exception as error:
        if(config.debug):
            print("\n[INFO] net.main() @ initial recv(): %s\n" % error)

    if(config.debug):
        if(buf):
            print("recv from target:\n%s\n" % buf)

    if(config.multibin or config.multistr):
        if(len(config.session) == 0):
            print("\n[ERROR] no session data to fuzz, check inputs\n")
            return FAILURE

        for s in config.session:
            if(config.multibin):
                sb = s # multibin is already bytes
            else:
                sb = bytearray(s.encode())

            #
            # standard send/recv bytes
            #
            if(misc.sendRecvBytes(sb) != SUCCESS):
                if(config.mode == settings.LOCAL_SERVER):
                    if(misc.isUnix()): # no repro with local server on win32
                        if(core.reproCrash(settings.FUZZ_FILE_PREV, cmdline, False) != SUCCESS):
                            if(config.debug):
                                print("[INFO] couldn't repro crash @ sendRecvBytes(sb)\n")
                            return FAILURE
                        else:
                            return SUCCESS
                elif((config.mode == settings.CLIENT) or (config.mode == settings.SERVER)):
                    if(config.broken_pipe):
                        config.broken_pipe = False
                        return SUCCESS
                    else:
                        return FAILURE
                else:
                    return FAILURE

            time.sleep(settings.SEND_RECV_TIME)

    #
    # byte-based single send
    #
    else:
        mutant = misc.readBytes(settings.FUZZ_FILE)

        if(mutant == None):
            print("\n[ERROR] net.main() @ reading fuzz file: %s\n" % settings.FUZZ_FILE)
            return FAILURE

        #
        # helper for udp clients
        #
        # note: Resource Temporarily Unavailable error is OK (no data to recv)
        #
        if(config.prot == 'udp'):
            if((config.mode == settings.CLIENT) or (config.mode == settings.LOCAL_CLIENT)):
                try:
                    (data, address) = config.conn.recvfrom(settings.RECV_SIZE)
                except Exception as error:
                    if(config.debug):
                        print("\n[INFO] net.main() @ udp recvfrom() failed: %s\n" % error)

        time.sleep(settings.SEND_RECV_TIME) # small delay

        #
        # crash scenario #2
        #
        # connect -> send (mutant)
        #
        # -> if send mutant fails, check for crash by repro'ing PREVIOUS fuzz file
        #
        # note: use send() not sendto() if already connected (UDP)
        #
        if(config.debug):
            print("\nsending data to target\n")

        try:
            if(config.prot == 'tcp'):
                config.conn.send(mutant)
            else: # udp is fun
                try:
                    config.conn.sendto(mutant, (config.host, config.port))
                except:
                    config.conn.send(mutant)

            if(config.debug):
                print("sent to target:\n%s\n" % mutant)
        except Exception as error:
            if(config.debug):
                print("\n[INFO] net.main() @ send mutant: %s\n" % error)

            if(config.mode == settings.LOCAL_SERVER):
                if(misc.isUnix()):
                    if(core.reproCrash(settings.FUZZ_FILE_PREV, cmdline, False) != SUCCESS):
                        if(config.debug):
                            print("[INFO] couldn't repro crash @ send(mutant)\n")
                        return FAILURE
                    else:
                        return SUCCESS

        time.sleep(settings.SEND_RECV_TIME) # delay

        #
        # crash scenario #3
        #
        # connect -> send -> recv
        #
        # -> if recv fails or is zero bytes, check for crash by repro'ing CURRENT fuzz file
        #
        if((config.multibin == False) and (config.multistr == False)):
            data = None

            try:
                if(config.prot == 'tcp'):
                    data = config.conn.recv(settings.RECV_SIZE)
                else:
                    data = config.conn.recvfrom(settings.RECV_SIZE)

                if(config.debug):
                    if(config.prot == 'tcp'):
                        print("\nrecv from target:\n%s\n" % data)
                    else:
                        print("\nrecv from target:\n%s\n" % data[0])
            #
            # unclear if even this is a reliable way to check if a UDP server went down
            #
            except ConnectionRefusedError as error:
                if((config.mode == settings.SERVER) or (config.mode == settings.LOCAL_SERVER)):
                    if(config.prot == 'tcp'):
                        if(config.debug):
                            if(misc.isUnix()):
                                print("\n[INFO] connection failed to %s -- check if the target crashed" % config.address)
                            else: # win32
                                print("\n[INFO] connection failed to %s -- can usually be ignored as its common on win32)" % config.address)
                    else: # udp
                        if(config.count == 1):
                            print("[ERROR] connection failed to %s\n" % config.address)
                            sys.exit(FAILURE)

                if((config.mode == settings.CLIENT) or (config.mode == settings.SERVER)):
                    if((config.attach == None) and (config.report_crash == False)):
                        if(misc.checkPort(config.prot, config.host, config.port) == False):
                            config.down = True
                            misc.clientServerCrash()
                            return FAILURE

                return SUCCESS
            except Exception as error:
                if(config.debug):
                    print("\n[INFO] net.main() @ recv from target: %s\n" % error)

                #
                # reproCrash() probably fails on UDP targets
                #
                if(config.mode == settings.LOCAL_SERVER):
                    if(misc.isUnix()):
                        if(core.reproCrash(settings.FUZZ_FILE_PREV, cmdline, False) != SUCCESS):
                            if(config.debug):
                                print("[INFO] couldn't repro crash @ send(mutant)\n")
                            return FAILURE
                        else:
                            return SUCCESS

            if(data != None):
                if((len(data) == 0) and (config.mode == settings.LOCAL_SERVER)):
                    if(misc.isUnix()):
                        if(core.reproCrash(settings.FUZZ_FILE, cmdline, False) != SUCCESS):
                            if(config.debug):
                                print("[INFO] couldn't repro crash @ send(mutant)\n")
                            return FAILURE
                        else:
                            return SUCCESS

        time.sleep(settings.SEND_RECV_TIME) # delay

    #
    # crash scenario #4
    #
    # connect -> send -> recv -> send (test)
    #
    # -> if send test data fails, check for crash by repro'ing CURRENT fuzz file
    #
    # note: do not send the test packet if we're fuzzing a session
    #
    if(settings.SEND_TEST_PACKET):
        if((config.multibin == False) and (config.multistr == False)):
            if((config.mode == settings.SERVER) or (config.mode == settings.LOCAL_SERVER)):
                if(config.debug):
                    print("\nsending test data to target\n")

                try:
                    if(config.prot == 'tcp'):
                        config.conn.send(settings.TEST_DATA)
                    else:
                        config.conn.send(settings.TEST_DATA)

                    if(config.debug):
                        print("sent test data to target:\n%s\n" % settings.TEST_DATA)
                except Exception as error:
                    if(config.debug):
                        print("\n[INFO] net.main() @ send test: %s\n" % error)

                    if(config.mode == settings.LOCAL_SERVER):
                        if(misc.isUnix()):
                            if(core.reproCrash(settings.FUZZ_FILE, cmdline, False) != SUCCESS):
                                if(config.debug):
                                    print("[INFO] couldn't repro crash @ send(test)\n")
                                return FAILURE
                            else:
                                return SUCCESS

        if(config.process != None):
            try:
                config.process.communicate(timeout=(config.maxtime * settings.NETWORK_TIMEOUT_MULTIPLE))
            except Exception as error:
                if(config.debug):
                    print("\n[INFO] net.main() @ process communicate: %s\n" % error)

        if(config.attach):
            if(triage.checkDebugger(cmdline) == SUCCESS):
                if(config.debug):
                    print("triage.checkDebugger() found a crash\n")
            else:
                if(config.debug):
                    print("triage.checkDebugger() did not find a crash\n")

    #
    # keep track of network execution times for stats
    #
    if(len(config.exec_times) <= settings.MAX_AVG_EXEC):
        config.exec_times.append(timer() - startTime)

    #
    # we don't want to check the return code if we're running inside a debugger
    #
    if((cmdline != None) and (config.process != None)):
        if((config.insulate == False) and (config.mode != settings.LOCAL_SERVER)):
            misc.checkForCrash(cmdline)

    return SUCCESS

#
# fuzz network servers
#
# takes care of setup for the connection, TLS, etc
#
def startClient(cmdline, replay):
    if(config.debug):
        print("entering net.startClient()\n")

    if(config.prot == 'tcp'):
        if(config.debug):
            print("starting tcp client\n")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.setblocking(0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(config.maxtime * settings.NETWORK_TIMEOUT_MULTIPLE)
        except Exception as error:
            print("\n[ERROR] net.startClient() @ tcp main socket: %s\n" % error)
            return FAILURE

        if(config.tls):
            try:
                conn = config.context.wrap_socket(sock)
            except Exception as error:
                print("\n[ERROR] socket SSL error: %s\n" % error)
                return FAILURE
        else:
            conn = sock

        config.conn = conn

    if(config.prot == 'udp'):
        if(config.debug):
            print("starting udp client\n")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(config.maxtime)

            if(misc.isUnix()): # win32 doesn't like this
                sock.setblocking(0)
        except Exception as error:
            print("\n[ERROR] net.startClient() @ udp main socket: %s\n" % error)
            return FAILURE

        config.conn = sock

    if(config.debug):
        print("started built-in client successfully")

    #
    # local client/server mode
    #
    if(config.mode == settings.LOCAL_SERVER):
        if(cmdline != None):
            if(replay):
                if(misc.isWin32()):
                    thread = threading.Thread(target=run.main, args=(cmdline,)).start()
                else:
                    if(debug.main(cmdline) != SUCCESS):
                        if(config.debug):
                            print("[ERROR] failed to start target server in debugger for replay")
                    else:
                        if(config.debug):
                            print("started target server in debugger successfully")
            else:
                if(localNetRun(cmdline) != SUCCESS):
                    if(config.debug):
                        print("[ERROR] failed to start target server")
                else:
                    if(config.debug):
                        print("started target server successfully")
        else:
            print("[INFO] cmdline=None, did not start the target server\n")

    return SUCCESS

#
# fuzz network clients
#
# works, but probably could be better with threading, etc
#
def startServer(cmdline, replay):
    if(config.debug):
        print("entering startServer()\n")

    if(config.prot == 'tcp'):
        if(config.debug):
            print("starting tcp server\n")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.setblocking(0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(config.maxtime)

            sock.bind((config.host, config.port))

            sock.listen(settings.TCP_BACKLOG)
        except Exception as error:
            print("\n[ERROR] net.startServer() @ tcp main socket: %s\n" % error)
            return FAILURE

    if(config.prot == 'udp'):
        if(config.debug):
            print("starting udp server\n")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(config.maxtime)

            if(misc.isUnix()):
                sock.setblocking(0)

            sock.bind((config.host, config.port))
        except Exception as error:
            print("\n[ERROR] net.startServer() @ udp main socket: %s\n" % error)
            return FAILURE

    if((config.mode == settings.LOCAL_CLIENT) or (config.mode == settings.LOCAL_SERVER)):
        if(cmdline != None):
            if(replay):
                debug.main(cmdline)
            else:
                localNetRun(cmdline)
        else:
            if(config.count == 1):
                print("[+] waiting for %d seconds for remote target client setup...\n" % settings.CLIENT_TIMEOUT)
                time.sleep(settings.CLIENT_TIMEOUT)

    if(config.debug):
        print("started target client successfully")

    #
    # network GUI clients may need this
    #
    if(config.key != None):
        misc.hitKey()

    if(config.prot == 'tcp'):
        config.cli_conn = None

        try:
            (ssock, config.cli_conn) = sock.accept()

            ssock.setblocking(0)
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ssock.settimeout(config.maxtime)

            if(config.tls):
                try:
                    conn = config.context.wrap_socket(ssock, server_side=True)
                except Exception as error:
                    print("\n[ERROR] socket SSL error: %s\n" % error)
                    return FAILURE
            else:
                conn = ssock
        except socket.timeout:
            if(config.debug):
                print("\n[INFO] timed out waiting for client connection: %s:%d\n" % (config.host, config.port))
            return FAILURE

        config.conn = conn

        if(config.debug):
            print("started built-in server successfully")

        if(config.cli_conn != None):
            if(config.debug):
                print("connection from %s\n" % config.cli_conn[0])

            sock.close()

    if(config.prot == 'udp'):
        config.conn = sock

        try:
            (data, address) = sock.recvfrom(settings.RECV_SIZE)
        except Exception as error:
            print("\n[INFO] net.startServer() @ udp recvfrom() failed: %s\n" % error)
            return FAILURE

    return SUCCESS

#
# local client/server mode
#
# only run target app once unless we are restarting it (eg. after a crash)
#
def localNetRun(cmdline):
    if(config.debug):
        print("entering localNetRun()\n")

    #
    # run insulated GUI network apps and network servers in a debugger
    #
    if(config.insulate or (config.mode == settings.LOCAL_SERVER)):
        if(config.count == 1):
            if(misc.isUnix()):
                debug.main(cmdline)
            else: # win32
                #
                # we use "this one cool trick" to make remote fuzzing work on win32 as on *nix, we
                # start just start the process or debugger and go, but on win32 we're using the
                # winappdbg engine which is blocking and times out before we hit our network code
                # to continue -- so we just create a thread and let it them run in bliss and harmony
                #
                thread = threading.Thread(target=run.main, args=(cmdline,)).start()

            #
            # give the user time to setup the interactive app
            #
            if(config.insulate):
                misc.doInsulate()
    #
    # local network clients
    #
    else:
        if(misc.isWin32()):
            thread = threading.Thread(target=run.main, args=(cmdline,)).start()
        else:
            run.main(cmdline)

    return SUCCESS

#
# replay crashes for confirmation
#
# core.repro() vs net.replay()
#
# - repro() tries to fully setup the environment and replay the crash for
# both local and network apps and calls replay() to handle network stuff
#
# - replay() is similar, but only handles the replay of network crashes
#
def replay(cmdline):
    if(config.debug):
        print("entering net.replay()\n")

    # print("replay_file=%s\n" % replay_file)

    if((config.mode == settings.CLIENT) or (config.mode == settings.LOCAL_CLIENT)):
        if(misc.isWin32()):
            startServerWin32(cmdline, replay) # win32 version
        else:
            startServer(cmdline, replay) # start built-in server to fuzz target client
    else:
        startClient(cmdline, replay) # start built-in client to fuzz target server

    if(config.conn == None):
        if(config.mode == settings.CLIENT):
            print("[ERROR] no connection from the client\n")
        else:
            print("[ERROR] net.replay() @ socket: no valid connection socket\n")
            misc.killTargetProcesses()
            sys.exit(FAILURE)

    if(config.mode == settings.SERVER or (config.mode == settings.LOCAL_SERVER)):
        try:
            config.conn.connect((config.host, config.port))
        except Exception as error:
            if(config.debug):
                print("\n[ERROR] net.replay() @ connect: %s\n" % error)
            return FAILURE

    #
    # initial replay recv()
    #
    buf = None

    try:
        if(config.prot == 'tcp'):
            buf = config.conn.recv(settings.RECV_SIZE)
        else:
            (buf, address) = config.conn.recvfrom(settings.RECV_SIZE)
    except Exception as error:
        if(config.debug):
            print("\n[INFO] net.main() @ initial recv(): %s\n" % error)

    if(config.debug):
        if(buf):
            print("recv from target:\n%s\n" % buf)

    if(config.multibin or config.multistr):
        if(len(config.session) == 0):
            print("\n[ERROR] no session data to replay, check inputs\n")
            return FAILURE

        for s in config.session:
            if(config.multibin):
                sb = s # multibin is already bytes
            else:
                sb = bytearray(s.encode())

            if(misc.sendRecvBytes(sb) != SUCCESS):
                return FAILURE

            time.sleep(settings.SEND_RECV_TIME)

    else:
        #
        # get mutant from file
        #
        mutant = misc.readBytes(config.replay_file)

        if(mutant == None):
            print("\n[ERROR] net.replay() @ reading replay file: %s\n" % config.replay_file)
            return FAILURE

        #
        # do recvfrom() first if udp
        #
        if(config.prot == 'udp'):
            try:
                (data, address) = config.conn.recvfrom(settings.RECV_SIZE)
            except Exception as error:
                if(config.debug):
                    print("\n[INFO] net.replay() @ udp recvfrom() failed: %s\n" % error)
                return FAILURE

        #
        # send data
        #
        if(config.debug):
            print("\nsending data to target\n")

        try:
            config.conn.send(mutant)

            if(config.debug):
                print("sent to target:\n%s\n" % mutant)
        except Exception as error:
            if(config.debug):
                print("\n[INFO] net.replay() @ send mutant: %s\n" % error)
            return FAILURE

        #
        # recv data
        #
        # note: only do this for non-session replays as we already recv() in misc.sendRecvBytes()
        #
        if((config.multibin == False) and (config.multistr == False)):
            try:
                if(config.prot == 'tcp'):
                    data = config.conn.recv(settings.RECV_SIZE)
                else:
                    data = config.conn.recvfrom(settings.RECV_SIZE)

                if(config.debug):
                    print("\nrecv from target:\n%s\n" % data)
            except Exception as error:
                if(config.debug):
                    print("\n[INFO] net.replay() @ recv from target: %s\n" % error)
                return FAILURE

            if((len(data) == 0) and (config.mode == settings.LOCAL_SERVER)):
                return FAILURE

        #
        # test send
        #
        if(settings.SEND_TEST_PACKET):
            if((config.mode == settings.SERVER) or (config.mode == settings.LOCAL_SERVER)):
                if(config.debug):
                    print("\nsending test data to target\n")

                try:
                    config.conn.send(settings.TEST_DATA)

                    if(config.debug):
                        print("sent test data to target:\n%s\n" % settings.TEST_DATA)
                except Exception as error:
                    if(config.debug):
                        print("\n[INFO] net.replay() @ send test data: %s\n" % error)
                    return FAILURE

    if(config.process != None):
        try:
            config.process.communicate(timeout=(config.maxtime * settings.NETWORK_TIMEOUT_MULTIPLE))
        except Exception as error:
            if(config.debug):
                print("\n[INFO] net.replay() @ process communicate: %s\n" % error)

    #
    # we don't want to check the return code if we're running inside a debugger
    #
    if((cmdline != None) and (config.process != None)):
        if((config.insulate == False) and (config.mode != settings.LOCAL_SERVER)):
            if(config.debug):
                print("net.replay() calling checkForCrash()\n")

            misc.checkForCrash(cmdline)

    return SUCCESS
