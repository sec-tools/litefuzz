#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# run.py
#

import os
import sys
import signal
import shutil
import subprocess32 as subprocess
import time
from time import time as timer

if(str(sys.platform).startswith('win32')):
    from winappdbg import *

try:
    FileNotFoundError # py3
except NameError:
    FileNotFoundError = IOError # py2

import triage
import debug
import misc
import config
import settings
from settings import SUCCESS, FAILURE

#
# choose your own adventure
#
def main(cmdline):
    if(misc.isUnix()):
        return unix(cmdline)
    elif(misc.isWin32()):
        return windows(cmdline)
    else:
        return FAILURE

#
# Linux/Mac binary execution support
#
def unix(cmdline):
    if(config.debug):
        print("current_input: %s\n" % config.current_input)
        print("cmdline:       %s\n" % cmdline)

    if(config.current_input == None):
        print("[ERROR] current_input cannot be None\n")
        return FAILURE

    if(settings.KILL_EXISTING_PROCESS):
        if(config.debug):
            print("killing any running processes named %s before running a new one\n" % config.target)

        misc.killProcessByName(config.target)

    startTime = timer()

    if(config.debug):
        print("\n[INFO] unix.run() @ starting target process: %s\n" % cmdline)

    #
    # capture stdout/stderr in a file
    #
    try:
        with open(settings.FUZZ_OUTPUT, 'w') as file:
            if('FUZZ' in cmdline):
                process = subprocess.Popen(cmdline,
                                           stdin=None,
                                           stdout=file,
                                           stderr=file,
                                           preexec_fn=os.setsid,
                                           env=config.env)
            else:
                process = subprocess.Popen(cmdline,
                                           stdin=open(config.current_input),
                                           stdout=file,
                                           stderr=file,
                                           preexec_fn=os.setsid,
                                           env=config.env)

            if(config.debug):
                print("unix.run() %s started @ pid=%d\n" % (cmdline, process.pid))

            #
            # do not timeout insulated apps (interactive apps)
            # and use sleep() instead of a process timeout if
            # client or server fuzzing is in progress
            #
            if(config.insulate == False):
                if(config.mode == settings.LOCAL):
                    (output, error) = process.communicate(timeout=config.maxtime)

                    if(error):
                        print("[ERROR] '%s' @ pid=%d: %s\n" % (cmdline, process.pid(), error))
                else:
                    time.sleep(config.maxtime)
    except subprocess.TimeoutExpired as error:
        if(config.debug):
            print("%s\n" % error)

        misc.killProcess(process.pid)
    except FileNotFoundError as error:
        print("[ERROR] run.unix() @ main run cmdline: %s" % error)
        sys.exit(FAILURE)
    except IOError as error:
        print("[INFO] run.unix() @ write(FUZZ_OUTPUT): %s" % error)
        return FAILURE
    except Exception as error:
        print("[ERROR] run.unix() failed: %s" % error)
        return FAILURE

    config.process = process

    #
    # keep track of execution times for stats
    #
    if(len(config.exec_times) <= settings.MAX_AVG_EXEC):
        config.exec_times.append(timer() - startTime)

    #
    # only do this for local apps in run.unix() because local
    # client and server runs call this in their own functions
    # because the process may not finish until after connection
    #
    if(config.mode == settings.LOCAL):
        misc.checkForCrash(cmdline)

    return SUCCESS

#
# make sure each process properly goes away after timeout
#
def win32KillAll(dbg):
    if(config.debug):
        print("entering run.win32KillAll()\n")

    for pid in dbg.get_debugee_pids():
        try:
            dbg.detach(pid)
            dbg.kill(pid)
        except:
            misc.killProcess(pid) # last ditch effort
            # pass

#
# Win32 binary execution support
#
# (based on https://winappdbg.readthedocs.io/en/latest/MoreExamples.html)
#
# note: stdin fuzzing not supported on win32
#
def windows(cmdline):
    if(config.debug):
        print("entering run.windows() with cmdline %s\n" % cmdline)

    if(settings.KILL_EXISTING_PROCESS):
        if(config.debug):
            print("killing any running processes named %s before running a new one\n" % config.target)

        misc.killProcessByName(config.target)

    with Debug(debug.win32CrashHandler, bKillOnExit = True) as dbg:
        try:
            dbg.execv(cmdline)
            System.set_kill_on_exit_mode(True)
        except Exception as error:
            print("\n[ERROR] run.windows() @ main run: %s\n" % error)
            sys.exit(FAILURE)

        config.dbg32 = dbg # so we can kill the eg. local server process as needed

        #
        # let local network servers join the '9 club
        #
        if(config.mode == settings.LOCAL_SERVER):
            maxtime = 9999999 # don't stop, running
        else:
            maxtime = config.maxtime

        timeout = timer() + maxtime

        while(dbg and timer() < timeout):
            try:
                dbg.wait(1000)
            except:
                continue

            try:
                try:
                    dbg.dispatch()
                except Exception as error:
                    if(config.debug):
                        print("[INFO] run.windows() @ dbg dispatch: %s" % error)
            finally:
                try:
                    dbg.cont()
                except Exception as error:
                    if(config.debug):
                        print("[INFO] run.windows() @ dbg continue: %s" % error)

        try:
            win32KillAll(dbg)
        except Exception as error:
            if(config.debug):
                print("[INFO] run.windows() @ dbg continue: %s" % error)
            # pass

    return SUCCESS
