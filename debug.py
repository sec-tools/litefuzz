#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# debug.py
#
#

import os
import sys
import glob
import shutil
import subprocess32 as subprocess
import time

if(str(sys.platform).startswith('win32')):
    from winappdbg import *

import core
import triage
import misc
import config
import settings
from settings import SUCCESS, FAILURE

#
# choose your own adventure 2
#
def main(cmdline):
    if(misc.isLinux()):
        return gdb(cmdline)
    elif(misc.isMac()):
        return lldb(cmdline)
    else: # winappdbg already handles this for win32
        return FAILURE

#
# Linux crash triage with the gdb debugger
#
def gdb(cmdline):
    if(config.debug):
        print("entering debug.gdb()\n")

    target = cmdline[0]
    args = cmdline[1:]

    debug_timeout = (config.maxtime * settings.DEBUG_TIMEOUT_MULTIPLE)

    #
    # if we only have a relative name for the target, get the full path for gdb
    #
    if(os.sep not in target):
        target = misc.getExePath(target)

    if(config.debug):
        print("target=%s, args=%s\n" % (target, args))

    debug_cmdline = []

    debug_cmdline.append('gdb')
    debug_cmdline.append('-q')

    debug_cmdline.append('-ex')
    debug_cmdline.append('file "' + target + '"')

    if(settings.DEBUG_ENV_EFENCE_GLIBC_ENABLE):
        debug_cmdline.append('-ex')

        #
        # set environment LD_PRELOAD /usr/lib/libefence.so
        # r ...
        #
        if(settings.DEBUG_ENV_EFENCE_ENABLE):
            debug_cmdline.append('set environment LD_PRELOAD ' + settings.LIBEFENCE_PATH)
        else:
            debug_cmdline.append('set environment ' + settings.GLIBC_MALLOC_CHECK) # fallback

    debug_cmdline.append('-ex')
    debug_cmdline.append('shell echo')

    debug_cmdline.append('-ex')

    run_cmdline = 'run '

    if(args != None):
        for arg in args:
            run_cmdline += arg + ' '

    run_cmdline = run_cmdline[:-1]

    debug_cmdline.append(run_cmdline)

    debug_cmdline.append('-ex')
    debug_cmdline.append('bt')

    debug_cmdline.append('-ex')
    debug_cmdline.append('shell echo')

    debug_cmdline.append('-ex')
    debug_cmdline.append('info registers')

    if(config.golang):
        debug_cmdline.append('-ex')
        debug_cmdline.append('disas $pc')
    else:
        # bang exploitable already provides a short disassembly, but it can fail
        debug_cmdline.append('-ex')
        debug_cmdline.append('x/4i $pc')

        debug_cmdline.append('-ex')
        debug_cmdline.append('exploitable -v')

    debug_cmdline.append('-ex')
    debug_cmdline.append('set confirm off')
    debug_cmdline.append('-ex')
    debug_cmdline.append('quit')

    if(config.debug):
        print("%s" % debug_cmdline)

    if(run(debug_cmdline, debug_timeout) == FAILURE):
        if(config.debug):
            print("debug.gdb() calling debug.run() failure\n")
        sys.exit(FAILURE)

    return SUCCESS

#
# Mac crash triage with the lldb debugger
#
# reference some stuff in https://github.com/bnagy/francis/blob/master/exploitaben/exploitaben.py
# it would be nice if one could get exploitaben working for !exploitable-like triage
#
def lldb(cmdline):
    if(config.debug):
        print("entering debug.lldb()\n")

    target = cmdline[0]
    args = cmdline[1:]

    debug_timeout = (config.maxtime * settings.DEBUG_TIMEOUT_MULTIPLE)

    if(config.debug):
        print("target=%s, args=%s\n" % (target, args))

    debug_cmdline = []

    debug_cmdline.append('lldb')

    debug_cmdline.append('-o')
    debug_cmdline.append('target create "' + cmdline[0] + '"')

    if(settings.DEBUG_ENV_GMALLOC_ENABLE):
        debug_cmdline.append('-o')
        debug_cmdline.append('settings set target.env-vars DYLD_INSERT_LIBRARIES=' + settings.LIBGMALLOC_PATH)
    else:
        if(settings.DEBUG_ENV_GLIBC_ENABLE):
            debug_cmdline.append('-o')
            debug_cmdline.append('settings set target.env-vars ' + settings.GLIBC_MALLOC_CHECK) # fallback

    debug_cmdline.append('-o')

    run_cmdline = 'run '

    if(args != None):
        for arg in args:
            run_cmdline += arg + ' '

    run_cmdline = run_cmdline[:-1]

    debug_cmdline.append(run_cmdline)

    debug_cmdline.append('-o')
    # debug_cmdline.append('bt 24')
    debug_cmdline.append('bt')

    debug_cmdline.append('-o')
    debug_cmdline.append('reg read')

    debug_cmdline.append('-o')
    debug_cmdline.append(settings.DEBUG_DISSASSEMBLE_LLDB)

    debug_cmdline.append('-o')
    debug_cmdline.append('quit')

    if(config.debug):
        print("\ndebug_cmdline: %s\n" % debug_cmdline)

    if(run(debug_cmdline, debug_timeout) == FAILURE):
        if(config.debug):
            print("debug.lldb() calling debug.run() failure\n")

        sys.exit(FAILURE)

    return SUCCESS

#
# debugger execution
#
def run(cmdline, timeout):
    if(config.debug):
        print("\nentering debug.run()\n")
        print("writing debug log to %s\n" % settings.FUZZ_INFO)

    if(settings.KILL_EXISTING_PROCESS):
        if(config.debug):
            print("killing any running processes named %s before running a new one\n" % config.target)

        misc.killProcessByName(config.target)

    #
    # try and prevent the new server from not starting because the port is still occupied
    #
    if(config.mode == settings.LOCAL_SERVER):
        if(misc.checkPort(config.prot, 'localhost', config.port)):
            if(config.process != None):
                misc.killProcess(config.process.pid)
                misc.killProcessByName(config.target)

    try:
        with open(settings.FUZZ_INFO, 'w') as file:
            if(settings.FUZZ_FILE in cmdline):
                process = subprocess.Popen(cmdline,
                                           stdin=None,
                                           stdout=file,
                                           stderr=file,
                                           preexec_fn=os.setsid)
            else:
                process = subprocess.Popen(cmdline,
                                           stdin=open(config.current_input),
                                           stdout=file,
                                           stderr=file,
                                           preexec_fn=os.setsid)

            if(config.mode == settings.LOCAL):
                (output, error) = process.communicate(timeout=timeout)

                if(error):
                    print("[ERROR] '%s' @ pid=%d: %s\n" % (cmdline, process.pid(), error))
            else:
                time.sleep(config.maxtime) # works, but no visibility into crashes
    except subprocess.TimeoutExpired as error:
        if(config.debug):
            print("%s\n" % error)

        misc.killProcess(process.pid)
    except Exception as error:
        print("[ERROR] debug.run() failed: %s\n" % error)

        try:
            file.write("debugger run failed: %s" % error)
        except Exception as error:
            print("[ERROR] debug.run() failed @ writing about it's failure: %s\n" % error)
            return FAILURE

        return FAILURE

    config.process = process

    if(config.insulate):
        config.insulate_pid = process.pid

    #
    # set this here to make sure we're current on the latest debugger runs
    #
    settings.FUZZ_INFO_STATIC = settings.FUZZ_INFO

    if(config.debug):
        print("debug.run() %s started @ pid=%d\n" % (cmdline, process.pid))

    return SUCCESS

#
# attach to a process
#
# Reference: https://opensource.apple.com/source/lldb/lldb-159/docs/lldb-for-gdb-users.txt.auto.html
#
def attach(debugger, pid):
    if(config.debug):
        print("entering debug.attach()\n")

    settings.KILL_EXISTING_PROCESS = False

    debug_timeout = 9999999 # don't... just don't

    debug_cmdline = []

    if(config.debug):
        print("debugger=%s and attaching to pid=%d\n" % (debugger, pid))

    if(debugger == 'gdb'):
        print("gdb support is unimplemented\n")
        return FAILURE

    if(debugger == 'lldb'):
        debug_cmdline.append('sudo') # usually needed for attaching
        debug_cmdline.append('lldb')

        debug_cmdline.append('-o')
        debug_cmdline.append('attach -p ' + str(pid)) # also attach --name NAME

        debug_cmdline.append('-o')
        debug_cmdline.append('continue')

        debug_cmdline.append('-o')
        debug_cmdline.append('bt')

        debug_cmdline.append('-o')
        debug_cmdline.append('reg read')

        #
        # command script import lldb.macosx.heap
        # malloc_info -S $rax
        #

        debug_cmdline.append('-o')
        debug_cmdline.append(settings.DEBUG_DISSASSEMBLE_LLDB)

        debug_cmdline.append('-o')
        debug_cmdline.append('detach')

        debug_cmdline.append('-o')
        debug_cmdline.append('quit')

        if(config.debug):
            print("\ndebug_cmdline: %s\n" % debug_cmdline)

        if(run(debug_cmdline, debug_timeout) == FAILURE):
            if(config.debug):
                print("debug.attach() calling debug.run() failure\n")

            sys.exit(FAILURE)

    return SUCCESS

#
# Windows console debugger crash triage with memory dumps via !analyze
#
# (winappdbg already has some !exploitable type analysis)
#
def win32Analyze():
    if(config.debug):
        print("entering debug.win32Analyze()\n")

    time.sleep(5) # delay to make sure WER has time to generate the dump file

    crash_dir = os.path.abspath(os.getcwd()) + os.sep + settings.CRASH_DIR

    hash = misc.getHash(misc.readBytes(settings.FUZZ_FILE))

    if(hash == None):
        hash = 'UNKNOWN'

    #
    # get pid and create paths to both generated dmp file and it's final location
    #
    dump_file_orig = settings.TMP_DIR + \
                     os.sep + \
                     misc.addExtExe(os.path.basename(config.target)) + \
                     '.' + \
                     str(config.memdump_pid) + \
                     '.dmp'

    dump_file = crash_dir + \
                os.sep + \
                misc.addExtExe(os.path.basename(config.target)) + \
                '.' + \
                str(config.memdump_pid) + \
                '_' + \
                hash + \
                '.dmp'

    dump_log = crash_dir + \
               os.sep + \
               misc.addExtExe(os.path.basename(config.target)) + \
               '.' + \
               str(config.memdump_pid) + \
               '_' + \
               hash + \
               '.log'

    if(config.debug):
        print("dump file = %s\n" % dump_file)
        print("dump file (orig) = %s\n" % dump_file_orig)

    try:
        shutil.copy(dump_file_orig, dump_file)
    except Exception as error:
        if(config.debug):
            print("\n[ERROR] debug.win32Analyze() @ copy dump file: %s\n" % error)
        return FAILURE

    timeout = (config.maxtime * settings.DEBUG_TIMEOUT_MULTIPLE)

    cmdline = []

    cmdline.append(settings.CONSOLE_DEBUGGER_PATH)

    cmdline.append('-kqm')
    cmdline.append('-nosqm')

    cmdline.append('-c')
    cmdline.append('.symfix; .reload; !analyze -v')

    cmdline.append('-z')
    cmdline.append(dump_file)

    #
    # pass dump file to console debugger and append output to fuzz info file
    #
    try:
        with open(dump_log, 'w') as file:
            process = subprocess.Popen(cmdline,
                                       stdin=None,
                                       stdout=file,
                                       stderr=file)

        (output, error) = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        if(config.debug):
            print("%s\n" % error)

        misc.killProcess(process.pid)
    except Exception as error:
        if(config.debug):
            print("[ERROR] debug.win32Analyze() failed: %s\n" % error)
        return FAILURE

    return SUCCESS

#
# Crash handler for win32
#
def win32CrashHandler(event):
    event_code = event.get_event_code()

    #
    # catch interesting crashes
    #
    if(event_code == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance()):
        if(config.debug):
            print("entering win32CrashHandler() with event code %d (last chance)\n" % event_code)

        config.crash = True

        exception_name = event.get_exception_name()

        if(exception_name != 'EXCEPTION_ACCESS_VIOLATION'):
            fault_type = exception_name
        else:
            fault_type = event.get_fault_type()

        process = Process(event.get_pid())
        cmdline = process.get_command_line()

        crash = Crash(event)
        info = crash.fullReport()

        if(config.debug):
            print("current_input: %s\n" % config.current_input)

        if(settings.MEMORY_DUMP):
            config.memdump_pid = event.get_pid()

        triage.win32(fault_type, cmdline, info)
