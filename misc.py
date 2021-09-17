#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# misc.py
#
#

import os
import sys
import re
import glob
import hashlib
import psutil
from psutil import NoSuchProcess
import shutil
import signal
import socket
import string
import subprocess
import shlex
import random
import time
from datetime import datetime, timedelta
from builtins import input
from tqdm import tqdm
import threading

# only import gui stuff if we're on linux /w X running or Windows
if((str(sys.platform).startswith('linux')) and os.environ.get('DISPLAY')):
    import pyautogui

if(str(sys.platform).startswith('darwin')):
    import pyautogui

if(str(sys.platform).startswith('win32')):
    import pyautogui
    from _winreg import *

try:
    BrokenPipeError # py3
except NameError:
    BrokenPipeError = socket.error # py2

import core
import debug
import run
import mutator
import triage
import config
import settings
from settings import SUCCESS, FAILURE
from settings import SIGTRAP, SIGABRT, SIGILL, SIGFPE, SIGSEGV, SIGGO

#
# check for duplicate crashes
#
def checkDup(pc):
    if(pc in config.pc_list):
        if(config.debug):
            print("\n[INFO] found duplicate crash: pc=%s\n" % pc)
        return True
    else:
        if(settings.CHECK_DUPS_PREV_RUN):
            for filename in os.listdir(settings.CRASH_DIR):
                if(pc in filename):
                    if(config.debug):
                        print("\n[INFO] found duplicate crash from previous run: pc=%s\n" % pc)
                    return True

    return False

#
# check for allowed chars
#
def checkAllowed(data):
    allowed = set(string.ascii_letters + \
                  string.digits + \
                  string.whitespace + \
                  '.' + '-' + ':' + '_' + '(' + ')' + '\\' + '/')

    return set(data) <= allowed

#
# checks paths and PATH to see if binary is installed
#
# source: https://stackoverflow.com/a/28909933
#
def checkForExe(name):
    if(config.debug):
        print("entering checkForExe() with name=%s\n" % name)

    if(isWin32()):
        name = addExtExe(name)

    if(os.path.isfile(name)):
        return True
    else:
        return any(
            (
                os.access(os.path.join(path, name), os.X_OK) and
                os.path.isfile(os.path.join(path, name))
            )
            for path in os.environ["PATH"].split(os.pathsep)
        )

#
# returns the full path for a given relative name of an executable
#
def getExePath(name):
    if(config.debug):
        print("entering getExecPath() with name=%s\n" % name)

    if(isWin32()):
        name = addExtExe(name)

    for path in os.environ["PATH"].split(os.pathsep):
        if(os.access(os.path.join(path, name), os.X_OK) and
           os.path.isfile(os.path.join(path, name))):
           full = os.path.join(path, name)
           break

    return full

#
# when fuzzing stuff where we aren't directly monitoring it in a
# debugger for crashes, use ReportCrash to check for crashes (mac)
#
def checkReportCrash():
    if(config.debug):
        print("entering checkReportCrash()\n")

    time.sleep(2) # give ReportCrash plenty of time to generate the crash artifacts

    try:
        files = glob.glob(settings.REPORT_CRASH_DIR + '/*')
    except Exception as error:
        print("\n[ERROR] misc.checkReportCrash() @ dir glob: %s\n" % error)
        return FAILURE

    if(os.sep in config.target):
        targets = config.target.split('/')
        target = targets[(len(targets) - 1)]
    else:
        target = config.target

    for file in files:
        if(str(os.path.basename(file)).startswith(target)):
            for report in config.report_list: # check for reports that were already there
                if(report == os.path.basename(file)):
                    return False

            if(config.debug):
                print("found new crash report '%s'\n" % os.path.basename(file))

            return True

    if(config.debug):
        print("no ReportCrash crash files found for %s\n" % target)

    return False

#
# get a list of files before fuzzing so we know what was already there
#
def checkReportCrashFiles():
    try:
        files = glob.glob(settings.REPORT_CRASH_DIR + '/*')
    except Exception as error:
        print("\n[ERROR] misc.checkReportCrashFiles() @ dir glob: %s\n" % error)
        return FAILURE

    for file in files:
        config.report_list.append(os.path.basename(file))

    return SUCCESS

#
# check if ReportCrash is running (mac)
#
def checkReportCrashRunning():
    if(config.debug):
        print("entering checkReportCrashRunning()\n")

    if(processExists('ReportCrash')):
        return True
    else:
        if(config.debug):
            print("[INFO] ReportCrash isn't running, trying to enable it...")

        try:
            subprocess.Popen(settings.REPORT_CRASH_LOAD, shell=True)
        except Exception as error:
            if(config.debug):
                print("\n[ERROR] misc.checkReportCrashRunning() @ run cmd: %s\n" % error)
            return False

        if(processExists('ReportCrash')):
            return True

    return False

#
# make sure directory is clean for new target runs
#
def checkReportCrashDirectory():
    if(config.debug):
        print("entering checkReportCrashDirectory()\n")

    try:
        os.makedirs(settings.REPORT_CRASH_DIR_OLD)
    except Exception as error:
        if(config.debug):
            print("\n[INFO] mkdir failed for ReportCrash old directory '%s': %s\n" % (settings.REPORT_CRASH_DIR_OLD, error)) # may already exist

    try:
        crash_files = glob.glob(settings.REPORT_CRASH_DIR + '/*')
    except Exception as error:
        print("\n[ERROR] misc.checkReportCrashDirectory() @ dir glob: %s\n" % error)
        return FAILURE

    for file in crash_files:
        if(os.path.basename(file).startswith(config.target)):
            if(config.debug):
                print("moving %s to reportcrash old directory\n" % os.path.basename(file))

            try:
                shutil.move(file, settings.REPORT_CRASH_DIR_OLD)
            except Exception as error:
                print("\n[ERROR] misc.checkReportCrashDirectory() @ dir glob: %s\n" % error)
                return FAILURE

    return SUCCESS

#
# check for input limits
#
def checkInput(file, files):
    if(os.path.getsize(file) == 0):
        if(len(files) == 1):
            print("\n[ERROR] input '%s' is an empty file" % os.path.basename(file))
        else:
            if(config.debug):
                print("\n[INFO] input '%s' is an empty file" % os.path.basename(file))
        return FAILURE

    #
    # disable more memory intensive mutators when fuzzing with big files
    #
    if(os.path.getsize(file) >= settings.BIG_INPUT_SIZE):
        if(config.debug):
            print("[INFO] found file %s is a big file (%d bytes), disabling memory intensive mutators\n")

        settings.INSERT_MUTATOR_ENABLE = False
        settings.REMOVE_MUTATOR_ENABLE = False
        settings.CARVE_MUTATOR_ENABLE = False
        settings.OVERWRITE_MUTATOR_ENABLE = False

    if(os.path.getsize(file) > settings.MAX_INPUT_SIZE):
        if(len(files) == 1):
            print("\n[ERROR] only (%d) input found and it's too big: %s (%d bytes > %d bytes limit)\n" % (len(files),
                                                                                                          os.path.basename(file),
                                                                                                          os.path.getsize(file),
                                                                                                          settings.MAX_INPUT_SIZE))
            sys.exit(FAILURE)
        else:
            if(config.debug):
                print("\n[INFO] input '%s' is too big (%d bytes limit)\n" % (os.path.basename(file),
                                                                             settings.MAX_INPUT_SIZE))
            return FAILURE

    return SUCCESS

#
# quick check to make sure input directory in valid
#
def checkInputDir(inputs):
    try:
        if(len(os.listdir(inputs)) == 0):
            print("[ERROR] input dir '%s' is empty\n" % inputs)
            return FAILURE
    except:
        print("[ERROR] input dir '%s' doesn't exist\n" % inputs)
        return FAILURE

    return SUCCESS

#
# check if target is up (tcp only)
#
def checkPort(prot, host, port):
    if(prot == 'tcp'):
        try:
            if(isWin32()):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                return (sock.connect_ex((host, port)) == 0)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    return (sock.connect_ex((host, port)) == 0)
        except Exception as error:
            if(config.debug):
                print("[INFO] misc.checkPort() failed @ connect_ex(): %s\n" % error)
            return False

    else:
        if(config.debug):
            print("[INFO] misc.checkPort() only supports TCP ports")

    return False

#
# check if hostname resolves
#
def checkHostname(host):
    try:
        socket.gethostbyname(host)
    except socket.error:
        return False

    return True

#
# check if IP address is valid
#
def checkIPAddress(ip):
    try:
        socket.inet_aton(ip)
    except socket.error:
        return False

    return True

#
# check return code for crashes
#
def checkForCrash(cmdline):
    if(config.debug):
        print("entering checkForCrash()\n")

    if(config.report_crash):
        if(checkReportCrash()):
            if(triage.reportCrash()):
                return triage.saveRepro(settings.FUZZ_FILE)

    if(config.process != None):
        if(config.debug):
            if(config.process.returncode):
                print("returncode=%d\n" % config.process.returncode)

        if(config.process.returncode == SIGABRT or
           config.process.returncode == SIGFPE  or
           config.process.returncode == SIGSEGV):
            return triage.unix(cmdline)

        if(config.golang):
            if(config.process.returncode == SIGGO):
                return triage.unix(cmdline)

    return SUCCESS

#
# check crash dir for crashes to reuse for fuzzing
#
def checkReuse(inputs):
    if(len(os.listdir(settings.CRASH_DIR)) == 0):
        print("\n[INFO] crash dir is empty, no crashes to reuse")
        return False

    extList = []
    files = []

    inputs = os.path.abspath(inputs)

    if(os.path.isdir(inputs)):
        try:
            files = glob.glob(inputs + '/*')
        except Exception as error:
            print("\n[ERROR] misc.checkReuse() @ inputs glob: %s\n" % error)
            return FAILURE
    else:
        files.append(inputs)

    for file in files:
        ext = getExt(file)

        if(ext == ''):
            extList.append('zz')
        else:
            extList.append(getExt(file))

    if(config.debug):
        print("%s" % extList)

    config.reusedir = inputs + '-' + 'reuse' + '-' + getRandomString(4)

    try:
        os.makedirs(config.reusedir)
    except Exception as error:
        print("\n[ERROR] can't mkdir reuse directory %s: %s" % (config.reusedir, error))
        return False

    #
    # 3) if no file extension, copy anything that's not *.out *.diff *.txt
    #
    try:
        files = glob.glob(settings.CRASH_DIR + '/*')
    except Exception as error:
        print("\n[ERROR] misc.checkReuse() @ CRASH_DIR glob: %s\n" % error)
        return FAILURE

    for file in files:
        for ext in extList:
            if(file.endswith(ext)):
                try:
                    shutil.copy(file, config.reusedir + os.sep + os.path.basename(file))
                except Exception as error:
                    print("\n[ERROR] misc.checkReuse() @ copy '%s' for reuse: %s\n" % (file, error))
                    return FAILURE

    return True

#
# removes the latest crashing files (eg. for test crash runs during minimization)
#
def cleanupMin():
    for file in os.listdir(settings.CRASH_DIR):
        if(os.path.basename(config.crash_file) in file):
            try:
                os.remove(settings.CRASH_DIR + os.sep + file)
            except Exception as error:
                if(config.debug):
                    print("\n[ERROR] couldn't remove '%s' test run file: %s\n" % (file, error))
                return FAILURE

    return SUCCESS

#
# removes the temp files and run directory (per-run dir, not the entire temp itself)
#
def cleanupTmp():
    try:
        shutil.rmtree(settings.RUN_DIR)
    except Exception as error:
        if(config.debug):
            print("\n[ERROR] couldn't remove run temp directory: %s\n" % error)
        return FAILURE

    if(config.static_fuzz_file != None):
        try:
            os.remove(config.static_fuzz_file)
        except Exception as error:
            if(config.debug):
                print("\n[ERROR] couldn't remove static fuzz file: %s\n" % error)
            return FAILURE

    return SUCCESS

#
# set target as crashed and get repro for remote client/server crashes
#
# note: previous fuzz file may be the only crasher available to save if next connect
# fails immediately (new fuzz file hasn't made it through the process to be created yet)
#
def clientServerCrash():
    newCrash()

    if(config.multibin):
        repro = None # we use config.session
    else:
        if(config.down):
            if(config.debug):
                print("[INFO] misc.clientServerCrash() is using %s (FUZZ_FILE_PREV) as repro\n" % settings.FUZZ_FILE_PREV)

            if(settings.FUZZ_FILE_PREV == None): # handle case where connection fails on first iteration (so no previous fuzz file)
                repro = settings.FUZZ_FILE
            else:
                repro = settings.FUZZ_FILE_PREV # fallback in case initial connect fails (so its previous iteration data)
        else:
            if(config.debug):
                print("[INFO] misc.clientServerCrash() is using %s (FUZZ_FILE) as repro\n" % settings.FUZZ_FILE)

            repro = settings.FUZZ_FILE

    return triage.saveRepro(repro)

#
# get the extension from a filename
#
def getExt(name):
    if('.' in name):
        ext = name.split('.')
        ext = ext[len(ext) - 1]
    else:
        ext = ''

    return ext

#
# windows is fun
#
def addExtExe(name):
    if('.exe' not in name):
        return name + '.exe'
    else:
        return name

#
# copy output to global output for visibility / debugging purposes
#
# copy .out file to /tmp/litefuzz/out for local apps and clients
# copy .txt file to /tmp/litefuzz/out for local servers and insulated apps (running in a debugger)
#
def copyDebugOutput():
    if(isWin32()): # no stdout support on windows
        return SUCCESS

    if((config.mode != settings.CLIENT) and (config.mode != settings.SERVER)):
        try:
            # if any([(config.mode == settings.LOCAL) or (config.mode == settings.LOCAL_CLIENT)]):
            if ((config.mode == settings.LOCAL) or (config.mode == settings.LOCAL_CLIENT)):
                if(config.insulate == False):
                    if(config.debug):
                        print("\ncopying %s to %s\n" % (settings.FUZZ_OUTPUT, settings.FUZZ_OUTPUT_DEBUG))

                    shutil.copy(settings.FUZZ_OUTPUT, settings.FUZZ_OUTPUT_DEBUG)
            else:
                if(config.debug):
                    print("\ncopying %s to %s\n" % (settings.FUZZ_INFO_STATIC, settings.FUZZ_OUTPUT_DEBUG))

                shutil.copy(settings.FUZZ_INFO_STATIC, settings.FUZZ_OUTPUT_DEBUG)
        except Exception as error:
            print("\n[ERROR] misc.copyDebugOutput() failed: %s\n" % error)
            return FAILURE

    return SUCCESS

#
# run timeout for insulate mode
#
def doInsulate():
    print("[+] waiting %d seconds for manual target setup before continuing...\n" % settings.INSULATE_TIMEOUT)
    time.sleep(settings.INSULATE_TIMEOUT)

#
# main page heap
#
def pageHeap(target):
    if(settings.DEBUG_ENV_PAGEHEAP_ENABLE):
        return doPageHeap(target, True)

    if(settings.DEBUG_ENV_PAGEHEAP_DISABLE):
        return doPageHeap(target, False)

    # else:
    #     if(checkPageHeap(target)):
    #         doPageHeap(target, False)
        # else:
        #     print("\n[INFO] PageHeap is off (pass -z to turn it on)\n")

#
# check if pageheap is enabled
#
def checkPageHeap(target):
    key = settings.PAGEHEAP_REG_KEY + os.path.basename(target)

    gf_val = None
    ph_val = None

    try:
        registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        k = OpenKey(registry, key)
        gf_val = QueryValueEx(k, 'GlobalFlag')
        ph_val = QueryValueEx(k, 'PageHeapFlags')
        CloseKey(k)
    except:
        return False

    if((gf_val[0] == settings.DEBUG_ENV_GFLAG_MAGIC) and
       (ph_val[0] == settings.DEBUG_ENV_PAGEHEAP_MAGIC)):
        return True
    else:
        return False

#
# check if pageheap is enabled
#
def checkMemoryDump(target):
    target = addExtExe(target)
    key = settings.MEMORY_DUMP_REG_KEY + os.path.basename(target)

    val = None

    try:
        registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        k = OpenKey(registry, key)
        CloseKey(k)
    except:
        return False

    return True

#
# enable memory dumps on win32
#
def doMemoryDump(target, enable):
    target = addExtExe(target)

    key = settings.MEMORY_DUMP_REG_KEY + os.path.basename(target)

    if(config.debug):
        print("\ndump key: %s" % key)

    if(enable and checkMemoryDump(target)):
        return SUCCESS
    elif(enable and (checkMemoryDump(target) == False)):
        try:
            CreateKey(HKEY_LOCAL_MACHINE, key)
            k = OpenKey(HKEY_LOCAL_MACHINE, key, 0, KEY_WRITE)
            SetValueEx(k, 'DumpFolder', 0, REG_SZ, settings.TMP_DIR) # place in the litefuzz tmp dir, later cp to crash dir
            CloseKey(k)
        except Exception as error:
            print("\n[ERROR] writing to registry failed: %s\n" % error)
            print("(try running elevated or use sudo.. really ;)\n") # gsudo for win32
            sys.exit(FAILURE)

        if(config.debug):
            print("\n[INFO] turned Memory Dumps on")
    else: # disable
        if(checkMemoryDump(target) == False):
            return SUCCESS

        if(config.debug):
            print("disabling Memory Dumps\n")

        try:
            registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
            k = OpenKey(registry, key)
            info = QueryInfoKey(k)

            for x in range(0, info[0]):
                sk = EnumKey(k, 0)

                DeleteKey(k, sk)

            DeleteKey(k, '')
            CloseKey(k)
        except Exception as error:
            print("\n[ERROR] failed to delete Memory Dump reg keys: %s\n" % error)
            print("(try running elevated or use sudo.. really ;)\n") # gsudo for win32
            sys.exit(FAILURE)

    return SUCCESS

#
# call checkPageHeap() and turn it on if requested
#
def doPageHeap(target, enable):
    if(isWin32()):
        target = addExtExe(target)

    key = settings.PAGEHEAP_REG_KEY + os.path.basename(target)

    if(config.debug):
        print("\ngflags key: %s" % key)

    if(settings.DEBUG_ENV_PAGEHEAP_ENABLE):
        if(enable and checkPageHeap(target)):
            return SUCCESS

        if(enable and (checkPageHeap(target) == False)):
            try:
                CreateKey(HKEY_LOCAL_MACHINE, key)
                k = OpenKey(HKEY_LOCAL_MACHINE, key, 0, KEY_WRITE)
                SetValueEx(k, 'GlobalFlag', 0, REG_SZ, settings.DEBUG_ENV_GFLAG_MAGIC)
                SetValueEx(k, 'PageHeapFlags', 0, REG_SZ, settings.DEBUG_ENV_PAGEHEAP_MAGIC)
                CloseKey(k)
            except Exception as error:
                print("\n[ERROR] writing to registry failed: %s\n" % error)
                print("(try running elevated or use sudo.. really ;)\n") # gsudo for win32
                sys.exit(FAILURE)

            if(config.debug):
                print("\n[INFO] turned PageHeap on")
    else: # disable
        if(checkPageHeap(target) == False):
            return SUCCESS

        if(config.debug):
            print("disabling PageHeap\n")

        try:
            registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
            k = OpenKey(registry, key)
            info = QueryInfoKey(k)

            for x in range(0, info[0]):
                sk = EnumKey(k, 0)

                DeleteKey(k, sk)

            DeleteKey(k, '')
            CloseKey(k)
        except Exception as error:
            # print("\n[ERROR] failed to delete PageHeap reg keys: %s\n" % error)
            # print("(try running elevated or use sudo.. really ;)\n") # gsudo for win32
            # sys.exit(FAILURE)
            pass
    # else:
    #     if(checkPageHeap(target)):
    #         if(config.debug):
    #             print("[INFO] PageHeap is still on (pass -z to make this explicit or -zz to turn off)\n")

    return SUCCESS

#
# flashy counter
#
def displayCount(pb, iterations, fuzz):
    #
    # only select the first n times
    #
    if(len(config.exec_times) == 0):
        config.exec_avg = (config.maxtime * 3)
    else:
        if(len(config.exec_times) <= settings.MAX_AVG_EXEC):
            if(config.mode == settings.LOCAL):
                config.exec_avg = (sum(config.exec_times) / len(config.exec_times)) * 4 # more accurate
            else:
                config.exec_avg = sum(config.exec_times) / len(config.exec_times)

    #
    # total iterations
    #
    if(iterations != 0): # minimization
        config.iterations = iterations

    remaining = str(timedelta(seconds=(config.iterations - config.count) * config.exec_avg)).split('.')[0]

    if(fuzz):
        pb.set_description_str("@ %d/%d (%d crashes, %d duplicates, ~%s remaining)" % (config.count,
                                                                                       config.iterations,
                                                                                       config.crashes,
                                                                                       config.dups,
                                                                                       remaining))
    else:
        if(config.repro):
            pb.set_description_str("@ %d/%d (%d crashes, %d duplicates, %d -> %d bytes, ~%s remaining)" % (config.count,
                                                                                                           config.iterations,
                                                                                                           config.crashes,
                                                                                                           config.dups,
                                                                                                           config.min_original,
                                                                                                           config.min_current,
                                                                                                           remaining))
        else:
            pb.set_description_str("@ %d/%d (%d new crashes, %d -> %d bytes, ~%s remaining)" % ((config.count + 1),
                                                                                                 config.iterations,
                                                                                                 config.crashes,
                                                                                                 config.min_original,
                                                                                                 config.min_current,
                                                                                                 remaining))

    pb.update(config.count)

#
# results
#
def displayResults():
    if((config.mode == settings.CLIENT) and config.down):
        print("\n[*] remote client stopped connecting, saving artifacts and exiting")

    if((config.mode == settings.SERVER) and config.down):
        print("\n[*] remote server stopped responding, saving artifacts and exiting")

    print("\n[RESULTS]")

    #
    # repro / min results
    #
    if(config.repro or config.min):
        if(config.min):
            config.count += 1

        if(config.crashes > 0):
            if(config.repro):
                if((config.mode == settings.CLIENT) or (config.mode == settings.SERVER)):
                    print("completed (%d) iterations with (%d) crash\n" % (config.count,
                                                                           config.crashes))
                else:
                    print("completed (%d) iterations with crash @ pc=%s\n" % (config.count,
                                                                              config.current_pc))
            else:
                print("completed (%d) iterations with %d new crashes found\n" % (config.count,
                                                                                 config.crashes))
        elif((config.crashes > 0) and (config.dups > 0)):
            print("completed (%d) iterations with %d new crashes found\n" % (config.count, config.crashes))
        elif(config.dups > 0):
            print("completed (%d) iterations with no new crashes found (%d dups)\n" % (config.count, config.dups))
        else:
            if(config.repro):
                print("completed (%d) iterations with no crashes found\n" % config.count)
            else:
                print("completed (%d) iterations with no additional crashes found\n" % config.count)

    #
    # fuzzing results
    #
    else:
        if((config.crashes > 0) and (config.dups == 0)):
            print("> completed (%d) iterations with (%d) unique crashes" % (config.count, config.crashes))
            print(">> check %s for more details\n" % settings.CRASH_DIR)
        elif((config.crashes > 0) and (config.dups > 0)):
            print("> completed (%d) iterations with (%d) unique crashes and %d dups" % (config.count, config.crashes, config.dups))
            print(">> check %s for more details\n" % settings.CRASH_DIR)
        elif((config.crashes == 0) and (config.dups > 0)):
            print("completed (%d) iterations with no new crashes found (%d dups)" % (config.count, config.dups))
            print(">> check %s for more details\n" % settings.CRASH_DIR)
        else:
            print("completed (%d) iterations with no crashes found\n" % config.count)

#
# main stats
#
def displayStats(cmdline, inputdir, inputs, file):
    #print("[CONFIG]")
    print("[STATS]")

    if(config.debug):
        print("pid:        %d" % os.getpid())

    print("run id:     %d" % config.run_id)

    if(cmdline != None):
        print("cmdline:    %s" % cmdline)

    if(config.address != None):
        print("address:    %s" % config.address)

    if(config.attach != None):
        print("process:    %s" % config.attach)

    print("crash dir:  %s" % settings.CRASH_DIR)

    if(config.min or config.repro):
        if(os.path.isfile(file)):
            print("crasher:    %s\n" % os.path.basename(file))
        else:
            print("crasher:    %s\n" % os.path.basename(os.path.normpath(file)))

    #
    # display only if fuzzing and not for minimization / replay
    #
    if((inputdir != None) and (inputs != None)):
        if(os.path.isdir(inputdir)):
            print("input dir:  %s" % config.inputs)
        else:
            print("input:      %s" % config.inputs)

        print("inputs:     %d" % inputs)
        print("iterations: %d" % config.iterations)

        if(settings.MUTATOR_CHOICE == 0):
            print("mutator:    random(mutators)\n")
        elif(settings.MUTATOR_CHOICE == settings.FLIP_MUTATOR):
            print("mutator:    flip\n")
        elif(settings.MUTATOR_CHOICE == settings.HIGHLOW_MUTATOR):
            print("mutator:    highlow\n")
        elif(settings.MUTATOR_CHOICE == settings.INSERT_MUTATOR):
            print("mutator:    insert\n")
        elif(settings.MUTATOR_CHOICE == settings.REMOVE_MUTATOR):
            print("mutator:    remove\n")
        elif(settings.MUTATOR_CHOICE == settings.CARVE_MUTATOR):
            print("mutator:    carve\n")
        elif(settings.MUTATOR_CHOICE == settings.OVERWRITE_MUTATOR):
            print("mutator:    overwrite\n")
        elif(settings.MUTATOR_CHOICE == settings.RADAMSA_MUTATOR):
            print("mutator:    radamsa\n")
        else:
            print("\n[ERROR] invalid mutator setting: %d" % settings.MUTATOR_CHOICE)
            sys.exit(FAILURE)

#
# execute a command (quietly)
#
def execute(cmd):
    if(config.debug):
        print("entering misc.execute()\n")

    cmdline = shlex.split(cmd)

    try:
        process = subprocess.Popen(cmdline,
                                   stdin=None,
                                   stdout=open(settings.null),
                                   stderr=open(settings.null))

        (output, error) = process.communicate(timeout=settings.EXEC_TIMEOUT)

        if(error):
                print("\n[ERROR] '%s' @ pid=%d: %s\n" % (cmdline, process.pid(), error))
    except subprocess.TimeoutExpired as error:
        if(config.debug):
            print("%s\n" % error)

        killProcess(process.pid)
    except Exception as error:
        print("\n[ERROR] misc.execute() cmd=%s: %s\n" % (cmdline, error))
        return FAILURE

    return SUCCESS

#
# generate certs for fuzzing
#
def generateCert():
    if(config.debug):
        print("entering misc.generateCert()\n")

    if(not os.path.isdir(settings.TLS_DIR)):
        try:
            os.mkdir(settings.TLS_DIR)
        except Exception as error:
            print("\n[ERROR] can't mkdir cert directory %s: %s" % (settings.TLS_DIR, error))
            return FAILURE

    if(execute(settings.GENERATE_CERT_CMD) != SUCCESS):
        return FAILURE

    if((os.path.isfile(settings.NETWORK_CRT) == False) or
       (os.path.isfile(settings.NETWORK_KEY) == False)):
        print("\n[ERROR] misc.generateCert() @ cert check: failed to create cert files\n")

    if(config.debug):
        print("\n[INFO] successfully generated certs for TLS")

    return SUCCESS

#
# returns a mutant based on the pick
#
def getMutant(data):
    mutations = getRandomInt(settings.MUTATION_MIN, settings.MUTATION_MAX)

    if(settings.MUTATOR_CHOICE == 0):
        pick = getRandomInt(1, settings.MUTATOR_MAX)
    else:
        pick = settings.MUTATOR_CHOICE

    #
    # check for disabled memory intensive mutators (eg. big files) and reassign the picks
    #
    if((pick == settings.INSERT_MUTATOR) and (settings.INSERT_MUTATOR_ENABLE == False)):
        pick = settings.FLIP_MUTATOR

    if((pick == settings.REMOVE_MUTATOR) and (settings.REMOVE_MUTATOR_ENABLE == False)):
        pick = settings.FLIP_MUTATOR

    if((pick == settings.CARVE_MUTATOR) and (settings.CARVE_MUTATOR_ENABLE == False)):
        pick = settings.HIGHLOW_MUTATOR

    if((pick == settings.OVERWRITE_MUTATOR) and (settings.OVERWRITE_MUTATOR_ENABLE == False)):
        pick = settings.HIGHLOW_MUTATOR

    if(pick == settings.FLIP_MUTATOR):
        mutant = mutator.flip(data, mutations)
    elif(pick == settings.HIGHLOW_MUTATOR):
        mutant = mutator.highLow(data)
    elif(pick == settings.INSERT_MUTATOR):
        mutant = mutator.insert(data)
    elif(pick == settings.REMOVE_MUTATOR):
        mutant = mutator.remove(data)
    elif(pick == settings.CARVE_MUTATOR):
        mutant = mutator.carve(data)
    elif(pick == settings.OVERWRITE_MUTATOR):
        mutant = mutator.overwrite(data)
    #
    # pyradamsa is supported for Linux + Py3 only
    #
    elif(pick == settings.RADAMSA_MUTATOR):
        if(isLinux() and (sys.version_info[0] >= 3)):
            if(settings.RADAMSA_MUTATOR_ENABLE):
                mutant = mutator.radamsa(data)
            else:
                mutant = mutator.flip(data, mutations)
        else:
            mutant = mutator.flip(data, mutations)
    else:
        if(config.debug):
            print("\n[INFO] unsupported mutator setting: %d\n" % mutator_pick)
            return None

    return mutant

#
# protocol:host:port -> protocol
#
def getProt(address):
    if(':' in address and (len(address.split(':')) == 3)):
        return address.split(':')[0]
    else:
        return None

#
# protocol:host:port -> host
#
def getHost(address):
    if(':' in address and (len(address.split(':')) == 3)):
        if('//' in address):
            return address.split(':')[1].strip('/')
        else:
            return None
    else:
        return None

#
# protocol:host:port -> port
#
def getPort(address):
    if(':' in address and (len(address.split(':')) == 3)):
        try:
            return int(address.split(':')[2])
        except:
            return None
    else:
        return None

#
# get hash
#
def getHash(data):
    return hashlib.sha256(data).hexdigest()

#
# get random size, considering the index, that fits within data_len and is not zero
#
def getWithin(i, data_len, size):
    if(size == 0):
        size = 1

    x = size

    while((i + x) > (data_len)):
        if(config.debug):
            print("[INFO] retrying i=%d, x=%d (max=%d)" % (i, x, (data_len - 1)))

        x = getRandomInt(0, size)

        if(x == 0):
            return x

    return x

#
# return random number (or zero) for mutations
#
# note: this may return zero for mutation of single byte inputs
#
def getRandomInt(min, max):
    if(min > max): # empty range for randrange() (1,1, 0)
        if(config.debug):
            print("[INFO] misc.getRandomInt() @ min=%d > max=%d, so setting min=0\n"% (min, max))

        min = 0

    if(max == 0): # if the data is one byte and we only have index zero, just return it
        if(config.debug):
            print("[INFO] misc.getRandomInt() @ max=0, so returning 0\n")

        return max

    random.seed(random.randrange(sys.maxsize))

    return random.randint(min, max)

#
# return random string by length
#
def getRandomString(len):
    random.seed(random.randrange(sys.maxsize))
    return ''.join(random.choice(string.ascii_lowercase) for c in range(len))

#
# return random size
#
# optimize for big inputs try to avoid hitting the loop in getWithin()
#
def getRandomSize(min, data):
    if(len(data) < 64):
        return getRandomInt(min, (len(data) - 1))
    elif(len(data) < 128):
        return getRandomInt(min, (len(data) // 2))
    elif(len(data) < 1024):
        return getRandomInt(min, (len(data) // 4))
    else:
        return getRandomInt(min, (len(data) // 8))

#
# press the selected key for GUI automation
#
def hitKey():
    if(config.debug):
        print("entering misc.hitKey()\n")

    if(isMac() and (config.key == 'cmd+r')): # at least support this... refreshing key
        try:
            pyautogui.hotkey('command', 'r')
        except Exception as error:
            print("[ERROR] misc.hitKey() @ pyautogui: %s" % error)
            return FAILURE
    else:
        try:
            pyautogui.press(config.key)
        except Exception as error:
            print("[ERROR] misc.hitKey() @ pyautogui: %s" % error)
            return FAILURE

    if(config.debug):
        print("pressed key %s\n" % config.key)

    return SUCCESS

#
# check on them 'wild PCs
#
def isWild(pc):
    if('0x' not in pc):
        pc = str('0x' + pc)

    try:
        if(int(pc, 16) > int(settings.USER_VA_MAX, 16)):
            return True
    except Exception as error:
        print("\n[ERROR] failed to parse PC=%s: %s\n" % (pc, error))

    return False

#
# check on them 'similar PCs
#
def isSimilar(first, second):
    if('0x' not in first):
        first = str('0x' + first)

    if('0x' not in second):
        second = str('0x' + second)

    try:
        if(int(second, 16) > (int(settings.SIMILAR_PC_RANGE, 16) + int(first, 16)) or
           int(second, 16) < (int(settings.SIMILAR_PC_RANGE, 16) - int(first, 16))):
            return False
    except Exception as error:
        print("\n[ERROR] failed to parse first=%s / second=%s: %s\n" % (first, second, error))

    return True

#
# write the invisible bell character to make sure the terminal stays active
#
# (trick that may come in handy for remote connections to unwieldy environments)
#
def keepAwake():
    if((config.iterations % 10 == 0)):
        sys.stdout.write('\a')
        sys.stdout.flush()

#
# many efforts to keep macs from falling asleep
#
def keepAwakeMac():
    if(checkForExe(settings.KYA_BIN)):
        for process in psutil.process_iter():
            if(settings.KYA_NAME in process.name()):
                if(config.debug):
                    print("\n[INFO] misc.keepAwake() process %s is already running\n")
                return FAILURE
        try:
            if not os.fork():
                os.system(settings.KYA_BIN)
        except Exception as error:
            if(config.debug):
                print("\n[ERROR] misc.keepAwake() @ run cmd: %s\n" % error)
            pass
    else:
        if(config.debug):
            print("\n[INFO] '%s' not found, install with brew to use it\n")

    return SUCCESS

#
# kill relevant processes
#
def killTargetProcesses():
    if(config.process != None):
        killProcess(config.process.pid)
        killProcessByName(config.target)

    if(config.insulate):
        if(config.insulate_pid != None):
            killProcess(config.insulate_pid)

    if(isWin32() and (config.mode == settings.LOCAL_SERVER)):
        run.win32KillAll(config.dbg32)

#
# standard kill process
#
def killProcess(pid):
    if(config.debug):
        print("entering killProcess() with pid=%d\n" % pid)

    try:
        if(isUnix()):
            os.killpg(pid, signal.SIGTERM)
        else: # win32
            os.kill(pid, signal.SIGTERM)
    except OSError as error:
        if(config.debug):
            print("\n[INFO] failed to terminate pid=%d: %s\n" % (pid, error))
    except Exception as error:
        if(config.debug):
            print("\n[INFO] failed to terminate pid=%d: %s (falling back to SIGKILL)\n" % (pid, error))

        try:
            if(isUnix()):
                os.killpg(pid, signal.SIGKILL)
            else: # win32
                os.kill(pid, signal.SIGKILL)
        except Exception as error:
            if(config.debug):
                print("\n[INFO] failed to kill pid=%d: %s\n" % (pid, error))
                return FAILURE

    return SUCCESS

#
# kill all processes containing name
#
def killProcessByName(name):
    if(config.debug):
        print("entering killProcessByName() with name=%s\n" % name)

    if(name == None):
        return FAILURE

    #
    # handle paths in name
    #
    if(os.sep in name):
        names = name.split(os.sep)
        name = names[len(names) - 1]

    try:
        for process in psutil.process_iter():
            if(name is str(process.name()).strip()):
                if(config.debug):
                    print("found %s in %s, killing pid=%d\n" % (name, process.name(), process.pid))

                return killProcess(process.pid)
    except Exception as error:
        if(config.debug):
            print("[ERROR] misc.killProcessByName() failed: %s\n" % error)
        return FAILURE

    return SUCCESS

#
# flip all the crash stuff
#
def newCrash():
    config.crash = True
    config.crashes += 1

#
# get unique (enough) run id
#
def newRunId():
    return random.randint(settings.RUN_ID_MIN, settings.RUN_ID_MAX)

#
# catch ctrl+c for pause or (hard) stop fuzzing
#
# note: kind of buggy doing this across platforms, but works ok for the first pause at least
#
def pauseFuzzer(signum, frame):
    signal.signal(signal.SIGINT, config.org_sigint)

    try:
        choice = (str(input("\n\nresume? (y/n)> ")))

        if(choice.lower().startswith('n')):
            raise KeyboardInterrupt
    except KeyboardInterrupt:
        try:
            cleanupTmp()

            if(config.process != None):
                killProcess(config.process.pid)

            if(config.insulate):
                killProcess(config.insulate_pid)

            if((config.mode != settings.CLIENT) and (config.mode != settings.SERVER)):
                killProcessByName(config.target)

            selfDestruct()
        except:
            sys.exit(FAILURE)

    print("\n")

#
# kill parent process
#
def selfDestruct():
    killProcess(os.getpid())

    if(isWin32()): # oh, windows
        run.win32KillAll(config.dbg32)
        execute("taskkill /f /im python.exe")

#
# checks and performs operations after delivering fuzzing payload to the target
#
def postIteration(cmdline):
    if(isWin32() and settings.MEMORY_DUMP):
        if(config.crash and (config.duplicate == False)):
            if(config.debug):
                print("[INFO] memory dumps enabled, calling win32Analyze()\n")

            #
            # must call it here instead of triage due to how we catch crashes on win32
            #
            dump_info = debug.win32Analyze()

    if(isWin32() and (config.mode == settings.LOCAL_SERVER)):
        if(config.crash):
            if(config.debug):
                print("[INFO] assuming local win32 server is down due to crash, doing a quick delay and restarting it\n")
            # run.win32KillAll(config.dbg32)
            thread = threading.Thread(target=run.main, args=(cmdline,)).start()
            time.sleep(config.maxtime * 2)

    config.crash = False
    config.duplicate = False

    if(config.cmd):
        execute(config.cmd)

    if(copyDebugOutput() != SUCCESS):
        if(config.debug):
            print("[ERROR] misc.postIteration() @ copyDebugOutput() failed\n")
            return FAILURE

    if((config.insulate == False) and (config.mode != settings.LOCAL_SERVER)):
        if(config.process != None):
            killProcess(config.process.pid)

    #
    # check on insulated process
    #
    # note: would require more tinkering, but could also replay the crash or triage via checkDebugger()
    #
    if(config.insulate):
        try:
            process = psutil.Process(config.insulate_pid)
        except:
            if(processExists(config.target)):
                process = psutil.Process(processPid(config.target))
            else:
                print("\n\n[!] insulated target appears to be down (pid=%d no longer exists)\n" % config.insulate_pid)

                newCrash()
                triage.saveRepro(settings.FUZZ_FILE)

                return FAILURE

        if(process != None):
            if(process.status() == psutil.STATUS_ZOMBIE):
                print("\n\n[!] insulated target appears to be down (pid=%d is defunct)\n" % config.insulate_pid)
                if(triage.checkDebugger(None) == SUCCESS): # confirm the crash
                    triage.saveRepro(settings.FUZZ_FILE) # save the repro if confirmed

                return FAILURE
        else:
            if(config.debug):
                print("[!] insulated target unknown failure, process may have crashed\n")

            if(triage.checkDebugger(None) == SUCCESS):
                triage.saveRepro(settings.FUZZ_FILE)

            return FAILURE

        if(process == None):
            return FAILURE

    if(settings.KEEPAWAKE_ENABLE):
        keepAwake()

    #
    # helps to fuzz interactive client GUIs such
    # as filezilla, maybe even web browsers, etc
    #
    if(config.key != None):
        hitKey()

    if(config.report_crash):
        checkForCrash(cmdline)

    if(config.rmfile):
        try:
            os.remove(config.rmfile)
        except Exception as error:
            if(config.debug):
                print("[ERROR] misc.postIteration() @ removing file %s failed: %s\n" % (config.rmfile, error))
                return FAILURE

    #
    # save previous session
    #
    if(config.multibin):
        config.session_prev = config.session

    if(config.mode != settings.LOCAL):
        config.conn.close()

    #
    # keep previous run data
    #
    if((config.count % 2) == 0):
        config.rmtemp = True

    return SUCCESS

#
# check if process exists
#
def processExists(name):
    if(os.sep in name):
        name = os.path.basename(name)

    if(config.debug):
        print("checking if a process by the name of '%s' exists...\n" % name)

    if(processPid(name) != None):
        return True

    return False

#
# get pid for process name
#
def processPid(name):
    try:
        for process in psutil.process_iter():
            if(name in process.name()):
                if(config.debug):
                    print("found %s @ pid=%d\n" % (name, process.pid))

                return process.pid # should return the first one found (if more than one)
    except:
        return None

    return None

#
# get pid for process name (do not rely on for high accuracy)
#
def processPid(name):
    if(os.sep in name):
        name = os.path.basename(name)

    if(config.debug):
        print("checking if a process by the name of '%s' exists...\n" % name)

    try:
        for process in psutil.process_iter():
            if(name in process.name()):
                if(config.debug):
                    print("found %s @ pid=%d\n" % (name, process.pid))

                return process.pid
    except:
        return None

    return None

#
# determine if a file is binary or string-based
#
def isBytes(path):
    try:
        with open(path, 'rb') as file:
            data = file.read().decode('utf-8')
    except UnicodeDecodeError:
        return True

    return False

#
# read bytes from a given file path
#
def readBytes(path):
    if(config.debug):
        print("\nentering readBytes() with path=%s\n" % path)

    try:
        with open(path, 'rb') as file:
            data = bytearray(file.read())
    except Exception as error:
        if(config.debug):
            print("\n[INFO] misc.readBytes() @ file read: %s" % error)
        return None

    return data

#
# write bytes to a given file path
#
def writeBytes(path, data):
    if(config.debug):
        print("\nentering writeBytes() with path=%s\n" % path)

    try:
        with open(path, 'wb') as file:
            if(type(data) == type(list())):
                for d in data:
                    file.write(d)
            else:
                file.write(data)
    except Exception as error:
        if(config.debug):
            print("\n[INFO] misc.writeBytes() @ file write: %s" % error)
        return FAILURE

    return SUCCESS

#
# generic send/recv bytes
#
def sendRecvBytes(data):
    if(config.prot == 'tcp'):
        try:
            config.conn.send(data)
        except BrokenPipeError as error:
            if(config.debug):
                print("\n[INFO] got BrokenPipe @ send(), connection is lost\n")
            config.broken_pipe = True
            return FAILURE
        except Exception as error:
            if(config.debug):
                print("\n[INFO] misc.sendRecvBytes() @ send(): %s\n" % error)

        if(config.debug):
            print("sent to target:\n%s\n" % data)

        buf = None

        try:
            buf = config.conn.recv(settings.RECV_SIZE)
        except Exception as error:
            if(config.debug):
                print("\n[INFO] misc.sendRecvBytes() @ recv(): %s\n" % error)

        if(config.debug):
            if(buf):
                print("recv from target:\n%s\n" % buf)
    else: # udp
        try:
            config.conn.send(data)
        except Exception as error:
            if(config.debug):
                print("\n[INFO] misc.sendRecvBytes() @ udp send() failed: %s\n" % error)
            return FAILURE

        try:
            (buf, address) = config.conn.recvfrom(settings.RECV_SIZE)
        except Exception as error:
            if(config.debug):
                print("\n[INFO] misc.sendRecvBytes() @ udp second recvfrom() failed: %s\n" % error)
            return FAILURE

    return SUCCESS

#
# reset counters after a test crash run
#
def resetCounters():
    config.crash = False

    if(config.supermin == False):
        config.crashes = 0

    config.duplicate = False
    config.dups = 0
    config.pc_list = []

#
#
#
def setupAddress():
    config.prot = getProt(config.address)
    config.host = getHost(config.address)
    config.port = getPort(config.address)

#
# check if malloc debugging is enabled and use
# electric fence, or fallback to malloc check
#
# same with gmalloc
#
def setupEnv():
    if(settings.DEBUG_ENV_EFENCE_GLIBC_ENABLE):
        if(config.debug):
            print("DEBUG_ENV_EFENCE_GLIBC_ENABLE\n")

        if(os.path.isfile(settings.LIBEFENCE_PATH)):
            config.env = settings.DEBUG_ENV_EFENCE
            settings.DEBUG_ENV_EFENCE_ENABLE = True
        else:
            config.env = settings.DEBUG_ENV_GLIBC
            settings.DEBUG_ENV_GLIBC_ENABLE = True
    elif(settings.DEBUG_ENV_GLIBC_ENABLE):
        if(config.debug):
            print("DEBUG_ENV_GLIBC_ENABLE\n")

        config.env = settings.DEBUG_ENV_GLIBC
    elif(settings.DEBUG_ENV_EFENCE_ENABLE):
        if(config.debug):
            print("DEBUG_ENV_EFENCE_ENABLE\n")

        config.env = settings.DEBUG_ENV_EFENCE
    elif(settings.DEBUG_ENV_GMALLOC_ENABLE):
        if(config.debug):
            print("DEBUG_ENV_GMALLOC_ENABLE\n")

        if(os.path.isfile(settings.LIBGMALLOC_PATH)):
            config.env = settings.DEBUG_ENV_GMALLOC
        else:
            config.env = settings.DEBUG_ENV_GLIBC
            settings.DEBUG_ENV_GLIBC_ENABLE = True
    else:
        if(config.debug):
            print("No malloc debuggers enabled\n")

        config.env = os.environ

#
# setup session data for multibin or multistr inputs
#
# - consume multibin binary session inputs sorted as 1, 2, 3, etc
# - consume multistr session inputs line by line from a single input
#
# note: multibin only uses files and multistr only uses data here
#
def setupSession(files, data):
    if(config.multibin):
        try:
            files.sort(key=lambda f: int(re.sub('\D', '', f)))
        except:
            print("\n[ERROR] session files are invalid (make sure they are numerically ordered)\n")
            return FAILURE

        for (i, file) in enumerate(files):
            try:
                config.session.append(readBytes(file))
            except Exception as error:
                print("[ERROR] misc.setupSession() @ reading binary data: %s\n" % error)
                return FAILURE
    else: # config.multistr
        try:
            session = data.decode()
        except Exception as error:
            print("[ERROR] fuzz.main() @ decoding '%s' as a string: %s\n" % (config.current_input, error))
            return FAILURE

        config.session = session.split('\n') # 0a

        while('' in config.session):
            config.session.remove('')

        for (i, s) in enumerate(config.session):
            # config.session[i] = (s + '\n') # add it back
            config.session[i] = (s + '\r\n') # add cr+lf back

        if(len(config.session) == 0):
            print("[ERROR] fuzz.main() @ identifying line breaks (\\n) in '%s': failed\n" % config.current_input)
            return FAILURE

    return SUCCESS

#
# setup the temp run directory files
#
def setupTmpRunDir():
    config.run_id = newRunId()

    #
    # make sure there isn't another temp directory with this same run id
    #
    while(os.path.isdir(settings.TMP_DIR + os.path.sep + str(config.run_id))):
        config.run_id = newRunId()

    #
    # eg. /tmp/litefuzz/1447
    #
    settings.RUN_DIR = settings.TMP_DIR + os.path.sep + str(config.run_id) + os.path.sep

    try:
        os.makedirs(settings.RUN_DIR)
    except Exception as error:
        print("\n[ERROR] can't mkdir temp run directory %s: %s" % (settings.RUN_DIR, error))
        return False

    if(config.debug):
        print("[INFO] run dir: %s\n" % settings.RUN_DIR)

    return True

#
# clean temp directory and setup next iteration with unique filenames
#
# note: for insulate / local servers, we keep them running in debuggers
# and don't want to remove the info (debugger output) file after each run
#
def setupNewIteration(cmdline):
    if(config.debug):
        print("entering setupNewIteration()\n")

    settings.FUZZ_FILE_PREV = settings.FUZZ_FILE

    try:
        files = glob.glob(settings.RUN_DIR + '/*')
    except Exception as error:
        print("[ERROR] misc.setupNewIteration() @ glob: %s\n" % error)
        return FAILURE

    #
    # keep previous run data for debugger-based or remote fuzzing sessions (eg. rmtemp is enabled for every other iteration)
    #
    if(config.rmtemp):
        for file in files:
            try:
                #
                # not debugger based, remote or insulated
                #
                if((config.mode == settings.LOCAL) and (config.insulate == False)):
                    if(os.path.basename(file).startswith('fuzz_')):
                        os.remove(file)
            except:
                if(config.debug):
                    print("\n[INFO] failed to remove temp file: %s\n" % file)
                pass # don't stop fuzzing just because debuggee hasn't been killed yet (win32 stuff)

        config.rmtemp = False

    name = getRandomString(8)

    #
    # trivia: some apps won't open the file if it doesn't have a known extension (*cough* Script Editor)
    #
    if(config.multibin):
        ext = 'zz'
    else:
        ext = getExt(config.current_input)

    if(ext != ''):
        config.file_ext = ext
    else:
        config.file_ext = 'zz'

    if(config.debug):
        print("ext=%s" % config.file_ext)

    if(config.static_fuzz_file == None):
        settings.FUZZ_FILE = settings.RUN_DIR + 'fuzz' + '_' + name + '.' + config.file_ext
    else:
        settings.FUZZ_FILE = config.static_fuzz_file

    #
    # minimization / repro mode
    #
    if(config.repro or config.min):
        settings.FUZZ_FILE = config.current_input

    if(config.min):
        if('.' in os.path.basename(settings.FUZZ_FILE)):
            ext = getExt(os.path.basename(settings.FUZZ_FILE))
            names = os.path.basename(settings.FUZZ_FILE).split('.')

            for i, name in enumerate(names):
                if(ext == name):
                    names[i] = 'min'

            names.append(ext)

            min_name = '.'.join(names)

            if(config.debug):
                print("%s" % min_name)

            settings.MIN_FILE = settings.CRASH_DIR + os.sep + min_name

        else:
            settings.MIN_FILE = settings.CRASH_DIR + os.sep + os.path.basename(settings.FUZZ_FILE) + '.min'

        if(config.debug):
            print("MIN_FILE=%s" % settings.MIN_FILE)

    settings.FUZZ_OUTPUT = settings.RUN_DIR + 'fuzz' + '_' + name + '.out'
    # settings.FUZZ_INFO = settings.RUN_DIR + 'fuzz' + '_' + name + '.txt'
    settings.FUZZ_DIFF = settings.RUN_DIR + 'fuzz' + '_' + name + '.diff'
    settings.FUZZ_DIFF_STRING = settings.RUN_DIR + 'fuzz' + '_' + name + '.diffs'
    settings.FUZZ_DIFF_ORIG = settings.RUN_DIR + 'fuzz' + '_' + name + '.diff.orig'
    settings.FUZZ_DIFF_FUZZ = settings.RUN_DIR + 'fuzz' + '_' + name + '.diff.fuzz'
    settings.FUZZ_OUTPUT_DEBUG = settings.TMP_DIR + os.sep + 'out'

    #
    # insulate mode runs the local app in a debugger, so FUZZ_INFO should be static
    #
    if(config.insulate):
        if(config.count == 0):
            settings.FUZZ_INFO = settings.RUN_DIR + 'fuzz' + '_' + name + '.txt'
    else:
        settings.FUZZ_INFO = settings.RUN_DIR + 'fuzz' + '_' + name + '.txt'

    #
    # first iteration will be FUZZ and thereafter will be FUZZ_FILE_PREV
    #
    if(cmdline != None):
        try:
            for i, cmd in enumerate(cmdline):
                if(config.debug):
                    print("current arg: %s" % cmd)

                    if(settings.FUZZ_FILE_PREV != None):
                        print("fuzz_file_prev: %s" % settings.FUZZ_FILE_PREV)

                if(cmd == 'FUZZ'):
                    cmdline[i] = settings.FUZZ_FILE

                    if(config.debug):
                        print("\nFUZZ -> %s\n" % settings.FUZZ_FILE)

                #
                # enable scenarios where you can use FUZZ to mitigate URL caching issues when fuzzing eg. web browsers
                #
                if(('FUZZ' in cmd) or (settings.FUZZ_FILE_PREV != None)):
                    if(settings.FUZZ_FILE_PREV != None):
                        if((cmd != settings.FUZZ_FILE_PREV) and (cmd.endswith(os.path.basename(settings.FUZZ_FILE_PREV)))):
                            cmdline_orig = cmdline[i]
                            cmdline[i] = cmdline[i].replace(os.path.basename(settings.FUZZ_FILE_PREV), os.path.basename(settings.FUZZ_FILE))

                            if(config.debug):
                                print("\n%s -> %s\n" % (cmdline_orig, cmdline[i]))
                    else:
                        cmdline_orig = cmdline[i]
                        cmdline[i] = cmdline[i].replace('FUZZ', os.path.basename(settings.FUZZ_FILE))

                        if(config.debug):
                            print("\n%s -> %s\n" % (cmdline_orig, cmdline[i]))

                if(settings.FUZZ_FILE_PREV != None):
                    if(cmd == settings.FUZZ_FILE_PREV):
                        cmdline[i] = settings.FUZZ_FILE

                        if(config.debug):
                            print("\n%s -> %s\n" % (settings.FUZZ_FILE_PREV, settings.FUZZ_FILE))
        except Exception as error:
            print("\n[ERROR] @ setupNewIteration(%s): %s\n" % (cmdline, error))
            return FAILURE

    return SUCCESS

#
# setup command line
#
def setupCmdline(cmdline):
    if(cmdline != None):
        org_cmdline = cmdline
        cmdline = transformCmdline(cmdline)

        if(cmdline[0].startswith('./')):
            config.target = cmdline[0].replace('./', '')
        else:
            config.target = cmdline[0]

        if(os.sep in config.target):
            # targets = config.target.split('/')
            targets = config.target.split(os.sep)
            config.target = targets[(len(targets) - 1)]

        if(config.debug):
            print("config.target = %s\n" % config.target)

        # if(isWin32()):
        #     pageHeap(config.target)
    else:
        org_cmdline = None

    return cmdline

#
# "the fun part: part duex"
#
# split at spaces yet handle *some* spaces in paths
#
def transformCmdline(cmdline):
    target = None
    found = False

    if(sys.platform == 'win32'):
        cmdline = cmdline.replace("\\", "\\\\")

    cmdline = shlex.split(cmdline)
    cmds = len(cmdline)

    i = 0

    if(config.debug):
        print("len(cmdline) = %d" % len(cmdline))

    target = cmdline[0]

    if(target.startswith('./')):
        target = target.replace('./', '')

    #
    # if we have any spaces, try and figure out what is the target;
    # we're going to be right most of the time even with relative paths,
    # and if not then the user can just provide the absolute path
    #
    if(cmds > 1):
        while((found == False) and (i < cmds)):
            app = cmdline[i]

            if(checkForExe(app)):
                target = app
                found = True
                break

            if((i + 1) < cmds):
                app = cmdline[i] + ' ' + \
                      cmdline[i + 1]

                if(checkForExe(app)):
                    target = app

                    cmdline[i] = target
                    cmdline.pop(i + 1)

                    found = True
                    break

            if((i + 2) < cmds):
                app = cmdline[i] + ' ' + \
                      cmdline[i + 1] + ' ' + \
                      cmdline[i + 2]

                if(checkForExe(app)):
                    target = app

                    cmdline[i] = target
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1) # since popping i+1 makes i+2 take its index

                    found = True
                    break

            if((i + 3) < cmds): # ok, we're gonna keep doing this I guess
                app = cmdline[i] + ' ' + \
                      cmdline[i + 1] + ' ' + \
                      cmdline[i + 2] + ' ' + \
                      cmdline[i + 3]

                if(checkForExe(app)):
                    target = app

                    cmdline[i] = target
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)

                    found = True
                    break

            if((i + 4) < cmds):
                app = cmdline[i] + ' ' + \
                      cmdline[i + 1] + ' ' + \
                      cmdline[i + 2] + ' ' + \
                      cmdline[i + 3] + ' ' + \
                      cmdline[i + 4]

                if(checkForExe(app)):
                    target = app

                    cmdline[i] = target
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)

                    found = True
                    break

            if((i + 5) < cmds): # psa: please limit spaces for directory names in paths for your apps :')
                app = cmdline[i] + ' ' + \
                      cmdline[i + 1] + ' ' + \
                      cmdline[i + 2] + ' ' + \
                      cmdline[i + 3] + ' ' + \
                      cmdline[i + 4] + ' ' + \
                      cmdline[i + 5]

                if(checkForExe(app)):
                    target = app

                    cmdline[i] = target
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)
                    cmdline.pop(i + 1)

                    found = True
                    break

            if(found):
                if(config.debug):
                    print("\n[INFO] guessed '%s' is the target (if not, try an absolute path)" % target)

            i += 1

    #
    # target can be a relative or absolute path, but don't try and run directories or non-existent files
    #
    if(os.path.isdir(target) or checkForExe(target) == False):
        print("\n[ERROR] target '%s' is invalid, please specify the full path to an executable\n" % target)
        sys.exit(FAILURE)

    if(config.debug):
        print("\ncmdline: %s\n" % cmdline)

    return cmdline

#
# various checks before fuzzing, eg. errors or just informational
#
def preChecks():
    if(os.path.isdir(settings.CRASH_DIR) == False):
        try:
            os.mkdir(settings.CRASH_DIR)
        except Exception as error:
            print("\n[ERROR] can't mkdir crash directory %s: %s" % (settings.CRASH_DIR, error))
            return False

    if(isLinux() and not checkForExe("gdb")):
        print("\n[ERROR] gdb was not found, please make sure it's installed and in PATH")
        return False

    if(isUnix() and not isLinux()):
        if(checkForExe("lldb") == False):
            print("\n[ERROR] lldb was not found, please make sure it's installed and in PATH")
            return False

    if(config.tls):
        if((os.path.isfile(settings.NETWORK_CRT) == False) or
           (os.path.isfile(settings.NETWORK_KEY) == False)):
            if(generateCert() != SUCCESS):
                print("\n[ERROR] failed to generate certs for fuzzing TLS-enabled targets")
                return False

    return True

#
# detect nix
#
def isUnix():
    if(str(sys.platform).startswith('linux') or
       str(sys.platform).startswith('darwin')):
       return True
    else:
        return False

#
# detect linux
#
def isLinux():
    if(str(sys.platform).startswith('linux')):
        return True
    else:
        return False

#
# detect mac
#
def isMac():
    if(str(sys.platform).startswith('darwin')):
        return True
    else:
        return False

#
# detect windows
#
def isWin32():
    if(str(sys.platform).startswith('win32')):
        return True
    else:
        return False
