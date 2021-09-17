#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# fuzz.py
#
#

import os
import sys
import glob
import psutil
import random
import re
import shutil
import select
import signal
import ssl
import time
from tqdm import tqdm

import core
import debug
import net
import run
import triage
import mutator
import misc
import config
import settings
from settings import SUCCESS, FAILURE
from settings import SIGABRT, SIGFPE, SIGSEGV

#
# where the magic begins
#
def main(cmdline, inputs):
    if(config.debug):
        print("entering fuzz.main()\n")

    if(misc.preChecks() == False):
        return FAILURE

    #
    # setup command line
    #
    if(cmdline != None):
        org_cmdline = cmdline
        cmdline = misc.setupCmdline(cmdline)
    else:
        org_cmdline = None

    #
    # network stuff
    #
    if(config.address != None):
        misc.setupAddress()

        if(None in (config.prot, config.host, config.port)):
            print("[ERROR] target address should be in proto://host:port format: %s\n" % config.address)
            return FAILURE

        if((misc.checkIPAddress(config.host) == False) and (misc.checkHostname(config.host) == False)):
            print("[ERROR] invalid ip or hostname: %s\n" % config.host)
            return FAILURE

        #
        # only do this check on remote servers as we're too early to have even started the local server
        #
        if(config.mode == settings.SERVER and config.prot == 'tcp'):
            if(config.prot == 'tcp'):
                if(misc.checkPort(config.prot, config.host, config.port) == False):
                    print("[ERROR] connection failed to %s\n" % config.address)
                    return FAILURE

    if(config.tls and (config.prot == 'udp')):
        print("[ERROR] TLS + UDP is not currently supported\n")
        return FAILURE

    #
    # optimize local client fuzzing speeds
    #
    if((config.insulate == False) and (config.mode == settings.LOCAL_CLIENT)):
        if(config.maxtime == 1): # only change "the default" for local clients
            if(misc.isWin32()): # win32 be more sensitive
                config.maxtime = (config.maxtime * 2) # slow it down
            else:
                config.maxtime = (config.maxtime / 4) # speed it up

    if(config.insulate or (config.mode == settings.LOCAL_SERVER)):
        config.try_again = True

    #
    # gather inputs
    #
    files = []

    if(os.path.isdir(inputs)):
        inputs = os.path.abspath(inputs)

        if(misc.checkInputDir(inputs) != SUCCESS):
            return FAILURE

        try:
            files = glob.glob(inputs + '/*')
        except Exception as error:
            print("[ERROR] fuzz.main() @ glob: %s\n" % error)
            return FAILURE
    else:
        files.append(os.path.abspath(inputs))

    #
    # if we made it this far, show stats
    #
    if(config.show_stats):
        misc.displayStats(org_cmdline, inputs, len(files), None)

    #
    # show progress
    #
    pb = tqdm(total=config.iterations, bar_format="{desc}")

    config.count = 0

    while config.count < config.iterations:
        if(config.down):
            if(config.debug):
                print("[INFO] config.down=True, breaking out of fuzzing run and exiting\n")
            break

        if(config.debug):
            print("-------------------------------- start iteration %d --------------------------------\n" % (config.count + 1))

        if(config.down):
            return SUCCESS

        if(os.path.isfile(inputs) == False):
            chosen_input = random.choice(files)

            while(misc.checkAllowed(chosen_input) == False):
                if(config.debug):
                    print("[INFO] skipping %s (special characters) as a chosen input\n" % os.path.basename(chosen_input))

                chosen_input = random.choice(files)

            while(os.path.isfile(chosen_input) == False):
                if(config.debug):
                    print("[INFO] skipping %s (not a file) as a chosen input\n" % os.path.basename(chosen_input))

                chosen_input = random.choice(files)

            #
            # check the validity of chosen input before using it
            #
            if(misc.checkInput(chosen_input, files) != SUCCESS):
                continue # skip to next input
            #
            # otherwise, just use the given input file
            #
        else:
            chosen_input = files[0]

            if(misc.checkInput(chosen_input, files) != SUCCESS):
                return FAILURE

        config.current_input = chosen_input

        if(config.debug):
            print("\ninput: %s" % os.path.basename(chosen_input))

        data = misc.readBytes(chosen_input)

        if(data == None):
            if(len(files) != 1):
                if(config.debug):
                    print("[INFO] couldn't read %s -- skipping\n" % chosen_input)
                continue
            else:
                print("[ERROR] fuzz.main() @ reading the only input provided '%s': failed\n" % chosen_input)
                return FAILURE

        #
        # make sure FUZZ_FILE_PREV gets created so remote network triage doesn't break
        #
        if(cmdline == None):
            cmdline = ['FUZZ']

        #
        # generate a unique fuzzing filename and set it in cmdline
        #
        if(misc.setupNewIteration(cmdline) == FAILURE):
            return FAILURE

        if(config.debug):
            print("\nwriting data to fuzz file @ %s\n" % settings.FUZZ_FILE)

        config.session = []

        #
        # call mutators with consideration of input options
        #
        if(config.multibin):
            if(config.debug):
                print("multibin session fuzzing enabled\n")

            if(misc.setupSession(files, None) != SUCCESS):
                return FAILURE

            n = misc.getRandomInt(0, (len(config.session) - 1))

            if(config.nofuzz == False):
                if(config.debug):
                    print("%s\n" % config.session[n])

                try:
                    config.session[n] = misc.getMutant(config.session[n])
                except Exception as error:
                    print("[ERROR] fuzz.main() @ getMutant for binary session: %s\n" % error)
                    return FAILURE

            misc.writeBytes(settings.FUZZ_FILE, config.session)
        elif(config.multistr):
            if(config.debug):
                print("multistr session fuzzing enabled\n")

            if(misc.setupSession(None, data) != SUCCESS):
                return FAILURE

            n = misc.getRandomInt(0, (len(config.session) - 1))
            s = bytearray(config.session[n].encode())

            if(config.nofuzz == False):
                try:
                    config.session[n] = misc.getMutant(s).decode(errors='replace')
                except Exception as error:
                    print("[ERROR] fuzz.main() @ getMutant for string session: %s\n" % error)
                    return FAILURE

                mutant = ''.join(config.session).encode()

                misc.writeBytes(settings.FUZZ_FILE, mutant) # fuzzing uses config.session, file is for artifacts only
            else:
                mutant = None
                data = ''.join(config.session).encode()

                misc.writeBytes(settings.FUZZ_FILE, data)
        else:
            if(config.nofuzz == False):
                mutant = misc.getMutant(data)

                if(mutant == None):
                    print("[ERROR] fuzz.main() @ mutant=None: mutation failed\n")
                    return FAILURE

                misc.writeBytes(settings.FUZZ_FILE, mutant)
            else:
                mutant = None
                misc.writeBytes(settings.FUZZ_FILE, data)

        config.count += 1

        #
        # adventure time
        #
        if(config.mode == settings.LOCAL):
            run.main(cmdline)
        elif((config.mode == settings.LOCAL_CLIENT) or (config.mode == settings.LOCAL_SERVER)):
            net.main(cmdline)
        else: # remote client and server mode
            if(config.attach or config.report_crash): # hybrid features
                net.main(cmdline)
            else: # no visibility, handle crashes without triage
                if(net.main(cmdline) != SUCCESS and config.count > 1):
                    misc.clientServerCrash()
                    misc.displayCount(pb, 0, True)

                    if(config.prot == 'tcp'): # tcp server support only
                        if(settings.TCP_KEEP_GOING):
                            print("\n\n[!] check if target down, sleeping %d seconds before trying to continue fuzzing...\n" % (settings.NET_SLEEP_TIME * 3))
                            time.sleep(settings.NET_SLEEP_TIME * 3)

                            if(misc.checkPort(config.prot, config.host, config.port) == False):
                                break

                            config.down = False
                        else:
                            break
                    else:
                        break

        misc.displayCount(pb, 0, True)

        if(misc.postIteration(cmdline) != SUCCESS):
            return FAILURE # something happened, exit fuzzing

        if(config.debug):
            print("-------------------------------- end iteration %d --------------------------------\n" % (config.count))

    pb.close()

    if((config.mode == settings.SERVER) and (config.prot == 'tcp')):
        if(misc.checkPort(config.prot, config.host, config.port) == False):
            if((config.attach == None) and (config.report_crash == False)):
                config.down = True

    misc.killTargetProcesses()

    return SUCCESS
