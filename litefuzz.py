#!/usr/bin/env -S python3 -Wignore
# -*- coding: UTF-8 -*-
#
# litefuzz.py
#
# litefuzz project
#
# A multi-platform fuzzer for poking at userland binaries and servers
#
#

import os
import platform
import sys
import signal

import core
import fuzz
import misc
import cli
import config
import settings
from settings import SUCCESS, FAILURE

class LiteFuzzer(object):
    def __init__(self, args):
        self.local = args.local
        self.client = args.client
        self.server = args.server
        self.cmdline = args.cmdline
        self.inputs = args.inputs
        self.iterations = args.iterations
        self.mutator = args.mutator
        self.address = args.address
        self.crashdir = args.crashdir
        self.tempdir = args.tempdir
        self.fuzzfile = args.fuzzfile
        self.maxtime = args.maxtime
        self.minfile = args.minfile
        self.supermin = args.supermin
        self.reprofile = args.reprofile
        self.reuse = args.reuse
        self.multibin = args.multibin
        self.multistr = args.multistr
        self.multinum = args.multinum
        self.insulate = args.insulate
        self.nofuzz = args.nofuzz
        self.key = args.key
        self.golang = args.golang
        self.tls = args.tls
        self.attach = args.attach
        self.cmd = args.cmd
        self.rmfile = args.rmfile
        self.reportcrash = args.reportcrash
        self.memdump = args.memdump
        self.nomemdump = args.nomemdump
        self.malloc = args.malloc
        self.nomalloc = args.nomalloc
        self.debug = args.debug

    def run(self):
        if(self.debug):
            config.debug = True

        if(config.debug):
            print("I'm running on %s with python %s\n" % (sys.platform, platform.python_version()))

        if(self.supermin != None):
            self.minfile = self.supermin
            config.supermin = True

        #
        # set mode
        #
        if(self.local and self.client):
            config.mode = settings.LOCAL_CLIENT
        elif(self.client):
            config.mode = settings.CLIENT
        elif(self.local and self.server):
            config.mode = settings.LOCAL_SERVER
        elif(self.server):
            config.mode = settings.SERVER
        elif(self.local):
            config.mode = settings.LOCAL
        else:
            if((self.minfile == None) and (self.reprofile == None)):
                print("[ERROR] must choose a fuzzing mode\n")
                return FAILURE

        if(self.reuse and (config.mode != settings.LOCAL)):
            print("[ERROR] reuse mode is only supported for local targets\n")
            return FAILURE

        if(config.debug):
            print("mode is %d\n" % config.mode)

        if((config.mode != settings.CLIENT) and (config.mode != settings.SERVER)):
            if(self.cmdline == None):
                print("[ERROR] local runs need cmdline\n")
                return FAILURE

        if(config.mode != settings.LOCAL):
            if(self.address == None):
                print("[ERROR] client or server modes need a target address containing host:port\n")
                return FAILURE
            else:
                config.address = self.address

        #
        # check for min or repro
        #
        if((self.minfile == None) and (self.reprofile == None)):
            config.fuzz = True
        else:
            if(self.minfile != None):
                config.min = True

            if(self.reprofile != None):
                config.repro = True

        #
        # allow users to just turn memory debugging on/off without fuzzing
        #
        if(self.inputs == None):
            if((config.min == False) and (config.repro == False)):
                if(misc.isWin32()):
                    if((self.malloc == False) and (self.nomalloc == False)):
                        if((self.memdump == False) and (self.nomemdump == False)):
                            print("[ERROR] input directory is required\n")
                            return FAILURE
                else:
                    print("[ERROR] input directory is required\n")
                    return FAILURE
            else:
                config.inputs = self.inputs # useful for determining fuzzing or config modes (eg. doHeapCheck)

        if(self.inputs != None):
            if((os.path.isdir(self.inputs)) == False and (os.path.isfile(self.inputs) == False)):
                print("[ERROR] %s is not a valid directory or file\n" % self.inputs)
                return FAILURE

        config.inputs = self.inputs

        if(config.min == False):
            config.iterations = self.iterations

        settings.MUTATOR_CHOICE = self.mutator

        if(self.crashdir != None):
            settings.CRASH_DIR = self.crashdir

        if(os.path.isdir(settings.CRASH_DIR) == False):
            try:
                os.makedirs(settings.CRASH_DIR)
            except Exception as error:
                print("[ERROR] could not create '%s' directory: %s\n" % (settings.CRASH_DIR, error))
                return FAILURE

        if(self.tempdir != None):
            settings.TMP_DIR = self.tempdir

        #
        # make the tmp directory if it doesn't exist
        #
        if(os.path.isdir(settings.TMP_DIR) == False):
            try:
                os.makedirs(settings.TMP_DIR)
            except Exception as error:
                print("[ERROR] could not create '%s' directory: %s\n" % (settings.TMP_DIR, error))
                return FAILURE

        if(misc.setupTmpRunDir() == False):
            return FAILURE

        if(self.fuzzfile != None):
            try:
                open(self.fuzzfile, 'wb')
            except Exception as error:
                print("[ERROR] invalid fuzz file '%s': %s\n" % (self.fuzzfile, error))
                return FAILURE

            config.static_fuzz_file = self.fuzzfile

        config.maxtime = float(self.maxtime)
        config.multibin = self.multibin
        config.multistr = self.multistr
        config.multinum = self.multinum
        config.insulate = self.insulate
        config.nofuzz = self.nofuzz
        config.key = self.key
        config.golang = self.golang
        config.tls = self.tls
        config.attach = self.attach
        config.cmd = self.cmd
        config.rmfile = self.rmfile

        if(config.insulate and misc.isWin32()):
            print("[ERROR] the insulate feature on Windows is not supported\n")
            return FAILURE

        #
        # note: you can still fuzz localhost as a "remote" target with attach (the lines blur a bit here)
        #
        if(config.attach):
            if(config.mode == settings.LOCAL):
                print("[ERROR] --attach currently only supports network fuzzing (choose a non-local for this one)\n")
                return FAILURE

            config.target = config.attach

        if(self.reportcrash != None):
            config.report_crash = True

            if(self.cmdline == None): # otherwise target is derived from cmdline
                config.target = self.reportcrash

            if(misc.isMac() == False):
                print("[ERROR] reportcrash is available on Mac only\n")
                return FAILURE

            if(misc.checkReportCrashRunning() == False):
                print("[ERROR] failed to turn on ReportCrash, please enable it and try again\n")
                return FAILURE

            misc.checkReportCrashDirectory()
            misc.checkReportCrashFiles()

        if(misc.isWin32()):
            if((config.mode != settings.CLIENT) and (config.mode != settings.SERVER)):
                target = misc.setupCmdline(self.cmdline)[0]

                if(misc.checkMemoryDump(target)): # if memdumps are already enabled, let the fuzzer know
                    settings.MEMORY_DUMP = True

                if(self.memdump or self.nomemdump):
                    if(self.memdump):
                        if(misc.doMemoryDump(target, True) == SUCCESS):
                            if(self.inputs == None):
                                print("\nMemory dumps turned ON for %s" % target)
                                return SUCCESS
                        else:
                            print("Failed to turn on memory dumps for %s" % target)

                            if(self.inputs == None):
                                 return FAILURE
                    else: # nomemdump
                        if(misc.doMemoryDump(target, False) == SUCCESS):
                            if(self.inputs == None):
                                print("\nMemory dumps turned OFF for %s" % target)
                                return SUCCESS
                        else:
                            print("Failed to turn off memory dumps for %s" % target)

                            if(self.inputs == None):
                                return FAILURE

        if((config.mode != settings.CLIENT) and (config.mode != settings.SERVER)):
            if(self.malloc):
                if(misc.isLinux()):
                    if(self.malloc == 'default'):
                        settings.DEBUG_ENV_EFENCE_GLIBC_ENABLE = True
                    elif(self.malloc == 'glibc'):
                        settings.DEBUG_ENV_GLIBC_ENABLE = True
                    else:
                        settings.DEBUG_ENV_EFENCE_ENABLE = True
                elif(misc.isMac()):
                    settings.DEBUG_ENV_GMALLOC_ENABLE = True
                elif(misc.isWin32()):
                    settings.DEBUG_ENV_PAGEHEAP_ENABLE = True

                    if(self.inputs == None):
                        target = misc.setupCmdline(self.cmdline)[0]

                        if(misc.doPageHeap(target, True) == SUCCESS):
                            print("\nPageHeap turned ON for %s" % target)
                            return SUCCESS
                        else:
                            print("Failed to turn on PageHeap on for %s" % target)
                            return FAILURE
                else:
                    print("\n[INFO] -z ignored, unsupported platform\n")

            if(self.nomalloc):
                settings.DEBUG_ENV_PAGEHEAP_DISABLE = True

                if(misc.isWin32()):
                    if(self.inputs == None):
                        target = misc.setupCmdline(self.cmdline)[0]

                        if(misc.doPageHeap(target, False) == SUCCESS):
                            print("\nPageHeap turned OFF for %s" % target)
                            return SUCCESS
                        else:
                            print("Failed to turn off PageHeap for %s" % target)
                            return FAILURE
                else:
                    print("\n[INFO] -zz ignored, memory debugging is set at runtime for non-Windows OS\n")

        if(config.mode == settings.LOCAL): # file or stdin fuzzing
            if(misc.isWin32() and ('FUZZ' not in self.cmdline)): # stdin fuzzing unsupported on win32
                print("[ERROR] keyword FUZZ required in cmdline (stdin fuzzing not supported on Windows)\n")
                return FAILURE

        if(config.debug):
            print("[INFO] tmp dir: %s\n" % settings.TMP_DIR)

        if(settings.KEEPAWAKE_ENABLE):
            misc.keepAwake()

            if(misc.isMac()):
                misc.keepAwake()

        misc.setupEnv()

        print("--========================--")
        print("--======| litefuzz |======--")
        print("--========================--\n")

        if(config.fuzz):
            ret = fuzz.main(self.cmdline, self.inputs)
            if(self.reuse):
                if(ret == FAILURE):
                    return FAILURE

                if(misc.checkReuse(self.inputs)):
                    print("\n[+] reusing crashes to grind on...\n")

                    config.show_stats = False

                    ret = fuzz.main(self.cmdline, os.path.relpath(config.reusedir))

                    config.iterations += self.iterations

        elif(config.min):
            ret = core.minimize(self.minfile,
                                self.cmdline,
                                self.malloc,
                                self.address)

            if(ret != SUCCESS):
                return FAILURE

            if(config.supermin and (config.min_hit == False)):
                print("[+] supermin activated, continuing...\n")

                config.show_stats = False

                while(config.min_hit == False):
                    ret = core.minimize(config.current_input, # kinda like reuse
                                        self.cmdline,
                                        self.malloc,
                                        self.address)

        elif(config.repro):
            ret = core.repro(self.reprofile,
                              self.cmdline,
                              self.malloc,
                              self.address)
        else:
            return FAILURE

        if(ret != SUCCESS):
            return FAILURE

        if(config.mode != settings.CLIENT):
            misc.displayResults()

        if(config.debug == False):
            misc.cleanupTmp()

        return SUCCESS

def main():
    global org_sigint

    signal.signal(signal.SIGINT, misc.pauseFuzzer)

    args = cli.arg_parse()
    lf = LiteFuzzer(args)

    result = lf.run()

    if(result > 0):
        sys.exit(FAILURE)

if(__name__ == '__main__'):
    main()
