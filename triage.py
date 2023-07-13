#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# triage.py
#
#

import os
import sys
import glob
import re
import shutil

import core
import net
import run
import debug
import misc
import config
import settings
from settings import SUCCESS, FAILURE
from settings import SIGTRAP, SIGABRT, SIGILL, SIGFPE, SIGSEGV, SIGGO

def main(cmdline):
    if(misc.isUnix()):
        return unix(cmdline)
    elif(misc.isWin32()):
        return win32(cmdline)
    else:
        return FAILURE

#
# check debugger for crashes
#
def checkDebugger(cmdline):
    if(config.debug):
        print("entering checkDebugger()\n")

    #
    # both local server and insulated apps should use FUZZ_OUTPUTS_DEBUG
    #
    if(config.mode == settings.LOCAL_SERVER): # as non-crashing server sessions may be reused and reading from unique log files may fail
        try:
            with open(settings.FUZZ_OUTPUTS_DEBUG, 'rb') as file: # in case we get bytes
                log = file.read().decode('utf-8', 'ignore')
        except Exception as error:
            print("\n[ERROR] triage.checkDebugger() @ read(FUZZ_OUTPUTS_DEBUG): %s\n" % error)
            return FAILURE
    else:
        try:
            with open(settings.FUZZ_INFO, 'rb') as file:
                log = file.read().decode('utf-8', 'ignore')
        except Exception as error:
            print("\n[ERROR] triage.checkDebugger() @ read(FUZZ_INFO): %s\n" % error)
            return FAILURE

    #
    # if we catch an exception, run triage
    #
    for (ex, code) in settings.EXCEPTIONS.items():
        if(ex in log):
            if(config.debug):
                print("[INFO] found exception %s in debugger\n" % ex)

            #
            # for insulated targets, just confirm the crash
            #
            if(config.insulate):
                misc.newCrash()

            else:
                config.returncode = code

                if(main(cmdline) != SUCCESS):
                    print("[ERROR] triage.checkDebugger() calling triage.main() failed\n")
                    return FAILURE

            #
            # if there is a crash, kill the process so we can cleanly restart it later
            #
            if(config.process != None):
                misc.killProcess(config.process.pid)
                misc.killProcessByName(config.target)

            return SUCCESS

    if(config.debug):
        print("[INFO] no crash found in debug log\n")

    return FAILURE # failed to find a crash

#
# save the repo and crash info on *nix OS
#
def unix(cmdline):
    if(config.debug):
        print("entering triage.unix()\n")

    info = "crash generated by mutating input '%s'\n\n" % os.path.basename(config.current_input)

    #
    # if we're in a debugger, don't use process.returncode
    #
    if(config.insulate or (config.mode == settings.LOCAL_SERVER)):
        returncode = config.returncode
    else:
        returncode = config.process.returncode

    #
    # if we attached it a process, use it for the cmdline / process name
    #
    if(config.attach):
        cmdline = [config.attach]

    if(returncode == SIGTRAP):
        fault = 'SIGTRAP'
        info += "cmdline %s exited with trace / breakpoint trap (%s)\n\n" % (cmdline, fault)
    elif(returncode == SIGABRT):
        fault = 'SIGABRT'
        info += "cmdline %s exited with abnormal termination condition (%s)\n\n" % (cmdline, fault)
    elif(returncode == SIGILL):
        fault = 'SIGILL'
        info += "cmdline %s exited with illegal instruction (%s)\n\n" % (cmdline, fault)
    elif(returncode == SIGFPE):
        fault = 'SIGFPE'
        info += "cmdline %s exited with floating point exception (%s)\n\n" % (cmdline, fault)
    elif(returncode == SIGSEGV):
        fault = 'SIGSEGV'
        info += "cmdline %s exited with invalid memory access (%s)\n\n" % (cmdline, fault)
    else:
        fault = 'UNKNOWN'
        info += "cmdline %s exited with %s\n\n" % (cmdline, fault)

    cmdl = ''

    for cmd in cmdline:
        cmdl += cmd + ' '

    info += '-> '

    if(settings.DEBUG_ENV_EFENCE_ENABLE):
        info += 'LD_PRELOAD=' + settings.LIBEFENCE_PATH + ' ' + cmdl + '\n\n'
    elif(settings.DEBUG_ENV_GLIBC_ENABLE):
        info += settings.GLIBC_MALLOC_CHECK + ' ' + cmdl + '\n\n'
    elif(settings.DEBUG_ENV_GMALLOC_ENABLE):
        info += 'DYLD_INSERT_LIBRARIES=' + settings.LIBGMALLOC_PATH + ' ' + cmdl + '\n\n'
    elif(settings.DEBUG_ENV_PAGEHEAP_ENABLE):
        info += 'enable pageheap + ' + cmdl + '\n\n'
    else:
        info += cmdl + '\n\n'

    if(config.debug):
        print("%s" % info)

    #
    # do a diff
    #
    if(settings.DIFF_ENABLE):
        if(misc.checkForExe("diff") and misc.checkForExe("od")):
            if(core.createDiff(config.current_input) != SUCCESS):
                print("[INFO] failed to create diff\n")

    #
    # auto-triage and create debug logs
    #
    # note: we already did triage beforehand for network apps to have FUZZ_INFO
    #
    if((config.mode == settings.LOCAL) or (config.mode == settings.LOCAL_CLIENT)):
        debug.main(cmdline)

    return saveCrash(fault, info)

#
# save the repo and crash info on Windows OS
#
# note: we've already got triage info from winappdbg,
# so don't need to run debuggers like on linux and mac
#
def win32(fault_type, cmdline, crash_info):
    if(config.debug):
        print("entering triage.win32()\n")

    info = "crash generated by mutating input '%s'\n\n" % os.path.basename(config.current_input)

    if(config.debug):
        print("%s" % info)
        print("fault_type=%s, cmdline=%s\n" % (fault_type, cmdline))

    if(fault_type == 0):
        fault = 'READ_AV'
    elif(fault_type == 1):
        fault = 'WRITE_AV'
    elif(fault_type == 8):
        fault = 'EXEC_AV'
    elif(str(fault_type) == 'EXCEPTION_INT_DIVIDE_BY_ZERO' or
                            'EXCEPTION_FLT_DIVIDE_BY_ZERO'):
        fault = 'DIV_BY_ZERO'
    else:
        fault = 'UNKNOWN_AV'

    if(cmdline != None):
        info += "%s encountered %s\n\n" % (cmdline, fault)
    else:
        info += "target encountered %s\n\n" % fault

    info += crash_info

    if(config.debug):
        print("%s" % info)

    #
    # do a diff
    #
    if(settings.DIFF_ENABLE):
        if(misc.checkForExe(settings.DIFF_WIN_BIN) and misc.checkForExe(settings.OD_WIN_BIN)):
            core.createDiff(config.current_input)
        else:
            print("\n[INFO] diff or od binaries not found, not doing a diff\n")

    return saveCrash(fault, info)

#
# save the crash info
#
def saveCrash(fault, info):
    if(config.debug):
        print("fault: %s" % fault)
        print("%s" % info)

    crash_info = None

    #
    # winappdbg (win32) has already given us this info
    #
    if(misc.isUnix()):
        #
        # both local server and insulated apps should use FUZZ_OUTPUTS_DEBUG
        #
        if(config.mode == settings.LOCAL_SERVER): # same as in checkDebugger()
            try:
                with open(settings.FUZZ_OUTPUTS_DEBUG, 'rb') as file: # in case we get bytes
                    crash_info = file.read().decode('utf-8', 'ignore')
            except Exception as error:
                print("\n[ERROR] triage.saveCrash() @ read(FUZZ_OUTPUTS_DEBUG): %s\n" % error)
                return FAILURE
        else:
            try:
                with open(settings.FUZZ_INFO, 'rb') as file:
                    crash_info = file.read().decode('utf-8', 'ignore')
            except Exception as error:
                print("\n[ERROR] triage.saveCrash() @ read(FUZZ_INFO): %s\n" % error)
                return FAILURE
    else:
        crash_info = info

    #
    # get pc
    #
    # Program received signal SIGSEGV, Segmentation fault.
    # 0x0000555555555136 in main ()
    #
    pc = None

    if(misc.isLinux()):
        pc = re.search('0x(.*)\sin', crash_info)

        if(pc != None):
            pc = pc.group(1).lstrip('0') # py2 compat
        else:
            pc = "UNKNOWN"

    if(misc.isMac()):
        pc = re.search('->\s+0x(.*)<', crash_info)

        if(pc != None):
            pc = pc.group(1).split(' ')[0]
        else:
            pc = "UNKNOWN"

    if(misc.isWin32()):
        pc = re.search('ip=(.*)', crash_info)

        if(pc != None):
            pc = pc.group(1).split(' ')[0].lstrip('0')
        else:
            pc = "UNKNOWN"

    if(config.debug):
        print("pc=%s\n" % pc)

    config.current_pc = pc

    #
    # check for a duplicate crash (if we're not doing a repro)
    #
    if(config.repro == False):
        if(misc.checkDup(pc)):
            if(config.debug):
                print("\n[INFO] crash (pc=%s) is a dup\n" % pc)

            config.duplicate = True
            config.dups += 1

            if(config.min and (config.min_pc == None)): # only the first one (crash repro)
                config.min_pc = pc

            return SUCCESS

    #
    # if not a duplicate, welcome to the party
    #
    config.crash = True

    if(config.min):
        if(config.current_pc != config.min_pc):
            config.crashes += 1
            config.pc_list.append(pc)
    else:
        config.crashes += 1
        config.pc_list.append(pc)

    if(config.min and (config.min_pc == None)):
        config.min_pc = pc

    #
    # get bucket
    #
    bucket = None

    if(misc.isLinux()):
        bucket = re.search('Classification:\s(.*)', crash_info)

        if(bucket != None):
            #bucket = bucket[1]
            bucket = bucket.group(1) # py2 compat

    if(misc.isMac()):
        bucket = re.search('stop\sreason\s=\s(.*)', crash_info)

        if(bucket != None):
            bucket = bucket.group(1).split(' ')[0]

            #
            # already caught SIGABRT once, don't need to capture it here too
            #
            if(bucket == 'signal'):
                bucket = None

    if(misc.isWin32()):
        bucket = re.search('Security\srisk\slevel:\s(.*)', crash_info)

        if(bucket != None):
            bucket = bucket.group(1).upper().replace(' ', '_')

    if(config.debug):
        print("%s" % info)

    if(settings.ARTIFACTS_ENABLE):
        try:
            # mutant = open(settings.FUZZ_FILE, 'rb').read()
            mutant = misc.readBytes(settings.FUZZ_FILE)
        except Exception as error:
            print("\n[ERROR] triage.saveCrash() @ read(FUZZ_FILE): %s\n" % error)
            return FAILURE

        if(bucket != None):
            hash_file = settings.CRASH_DIR + \
                        os.sep + \
                        bucket + \
                        '_' + \
                        fault + \
                        '_' + \
                        pc + \
                        '_' + \
                        misc.getHash(mutant)
        else:
            hash_file = settings.CRASH_DIR + \
                        os.sep + \
                        fault + \
                        '_' + \
                        pc + \
                        '_' + \
                        misc.getHash(mutant)

        settings.CRASH_FILE = hash_file

        hash_out = hash_file + '.out'
        hash_info = hash_file + '.txt'
        hash_diff = hash_file + '.diff'
        hash_sdif = hash_file + '.diffs'

        hash_file = hash_file + '.' + config.file_ext

        misc.writeBytes(hash_file, mutant)

        try:
            with open(hash_info, 'w') as file:
                file.write(info)

                if(crash_info == None):
                    print("\n[ERROR] triage.saveCrash() @ crash_info error\n")
                    return FAILURE

                #
                # we already have crash info from winappdbg for win32
                #
                if(misc.isUnix()):
                    file.write(crash_info)
        except Exception as error:
            print("\n[ERROR] triage.saveCrash() @ write(info): %s\n" % error)
            return FAILURE

        #
        # not an easy way to get stdout from the target in winappdbg yet
        #
        if(misc.isUnix()):
            if all([(config.insulate == False) and (config.mode != settings.LOCAL_SERVER) and (config.attach == None)]):
                try:
                    shutil.copy(settings.FUZZ_OUTPUT, hash_out)
                except Exception as error:
                    print("\n[ERROR] triage.saveCrash() @ copy FUZZ_OUTPUT: %s\n" % error)
                    return FAILURE

        if(settings.DIFF_ENABLE):
            try:
                shutil.copy(settings.FUZZ_DIFF, hash_diff)
            except Exception as error:
                print("\n[ERROR] triage.saveCrash() @ copy FUZZ_DIFF: %s\n" % error)
                return FAILURE

            try:
                shutil.copy(settings.FUZZ_DIFF_STRING, hash_sdif)
            except Exception as error:
                print("\n[ERROR] triage.saveCrash() @ copy FUZZ_DIFF_STRING: %s\n" % error)
                return FAILURE

        if(config.debug):
            print("> %s" % hash_file)

            if(misc.isUnix()):
                print("> %s" % hash_out)

            print("> %s" % hash_info)

            if(settings.DIFF_ENABLE):
                print("> %s" % hash_diff)
                print("> %s" % hash_sdif)

        #
        # if we've triaged a crash with multiple input files, save a replayable repro (only the crashing packet for multibin)
        #
        if(config.multibin or config.multistr):
            saveRepro(settings.FUZZ_FILE)

    return SUCCESS

#
# check mac reportcrash logs
#
def reportCrash():
    try:
        crash_files = glob.glob(settings.REPORT_CRASH_DIR + '/*')
    except Exception as error:
        print("\n[ERROR] triage.reportCrash() @ dir glob: %s\n" % error)
        return FAILURE

    for crash_file in crash_files:
        if(crash_file.endswith('.crash') and (os.path.basename(crash_file) not in config.report_list)):
            try:
                with open(crash_file, 'r') as file:
                    crash_info = file.read()
            except Exception as error:
                print("\n[ERROR] triage.reportCrash() @ read(%s): %s\n" % (crash_file, error))
                return FAILURE

            pc = re.search('0x(.*)', crash_info)

            if(pc != None):
                pc = pc.group(1).lstrip('0') # py2 compat
            else:
                pc = "UNKNOWN"

            if(misc.checkDup(pc)):
                if(config.debug):
                    print("\n[INFO] crash (pc=%s) is a dup\n" % pc)

                config.duplicate = True
                config.dups += 1

                return False

            else:
                misc.newCrash()
                config.current_pc = pc
                config.pc_list.append(config.current_pc)

            config.report_list.append(os.path.basename(crash_file)) # update report list for no dups afterwards

    return True

#
# save repros for insulated targets, remote clients / servers, reportcrash'ers
#
def saveRepro(file):
    if(config.debug):
        print("entering saveRepro() with file=%s\n" % file)

    if(config.mode == settings.CLIENT):
        target = 'CLIENT'
    elif(config.mode == settings.SERVER):
        target = 'SERVER'
    else:
        target = 'UNKNOWN'

    if(config.insulate):
        mode = 'INSULATED'
    else:
        mode = 'REMOTE'

    if(config.report_crash):
        mode = 'REPORTCRASH'

    #
    # setup repro
    #
    if(file != None):
        repro = misc.readBytes(file)

        if(repro == None):
            print("[ERROR] triage.saveRepro() failed @ misc.readBytes()\n")
            return FAILURE
    else:
        repro = bytes(config.session[0]) # workaround

    #
    # save the previous test case too
    #
    if(file == settings.FUZZ_FILE):
        if(config.count > 1): # no previous fuzz file if it's the first iteration
            repro_prev = misc.readBytes(settings.FUZZ_FILE_PREV)
        else:
            repro_prev = None
    elif(file == None):
        repro_prev = config.session_prev
    else:
        repro_prev = None

    if(config.multibin or config.multistr):
        if(config.multibin):
            if(len(config.session_prev) == 0):
                if(config.debug): # this is OK if it eg. crashes on first iteration (there is no previous session)
                    print("[ERROR] previous session data not found, cannot save this artifact\n")

        if(config.report_crash):
            hash_dir = settings.CRASH_DIR + \
                       os.sep + \
                       mode + \
                       '_' + \
                       target + \
                       '_' + \
                       config.host + \
                       '_' + \
                       str(config.port) + \
                       '_' + \
                       config.current_pc + \
                       '_' + \
                       misc.getHash(repro)
        elif(config.multibin):
            hash_dir = settings.CRASH_DIR + \
                       os.sep + \
                       mode + \
                       '_' + \
                       target + \
                       '_' + \
                       config.host + \
                       '_' + \
                       str(config.port) + \
                       '_' + \
                       misc.getHash(repro)
        else: # multistr
            hash_dir = settings.CRASH_DIR # no special dir for multistr, just write to crash dir

        #
        # could also add misc.getHash(repro_prev)
        #
        if(repro_prev != None):
            hash_dir_prev = settings.CRASH_DIR + \
                            os.sep + \
                            mode + \
                            '_' + \
                            target + \
                            '_' + \
                            config.host + \
                            '_' + \
                            str(config.port) + \
                            '_' + \
                            'PREV' + \
                            '_' + \
                            misc.getHash(repro)

            if(config.multibin):
                try:
                    # os.makedirs(hash_dir_prev)
                    os.makedirs(hash_dir_prev + os.sep + 'repro')
                except Exception as error:
                    if(config.debug):
                        print("\n[INFO] mkdir failed for repro prev directories %s\n" % error) # may already exist

    if(config.multibin):
        try:
            os.makedirs(hash_dir + os.sep + 'repro')
        except Exception as error:
            if(config.debug):
                print("\n[INFO] mkdir failed for repro directories %s\n" % error) # may already exist

        for (i, s) in enumerate(config.session):
            hash_out = hash_dir + \
                       os.sep + \
                       'repro' + \
                       os.sep + \
                       str(i + 1) + \
                       '.' + \
                       config.file_ext

            misc.writeBytes(hash_out, s)

        if(len(config.session_prev) != 0):
            for (i, s) in enumerate(config.session_prev):
                hash_out = hash_dir_prev + \
                           os.sep + \
                           'repro' + \
                           os.sep + \
                           str(i + 1) + \
                           '.' + \
                           config.file_ext

                misc.writeBytes(hash_out, s)

    if(config.multistr):
        hash_out = hash_dir + \
                   os.sep + \
                   mode + \
                   '_' + \
                   target + \
                   '_' + \
                   config.host + \
                   '_' + \
                   str(config.port) + \
                   '_' + \
                   misc.getHash(repro) + \
                   '.' + \
                   config.file_ext

        if(repro_prev != None):
            hash_out_prev = hash_dir + \
                            os.sep + \
                            mode + \
                            '_' + \
                            target + \
                            '_' + \
                            config.host + \
                            '_' + \
                            str(config.port) + \
                            '_' + \
                            misc.getHash(repro) + \
                            '_' + \
                            'PREV' + \
                            '.' + \
                            config.file_ext

            try:
                shutil.copy(settings.FUZZ_FILE_PREV, hash_out)
            except Exception as error:
                print("\n[ERROR] triage.saveRepro() @ copy repro prev (%s): %s\n" % (settings.FUZZ_FILE_PREV, error))
                return FAILURE

        if(file != None):
            try:
                shutil.copy(file, hash_out)
            except Exception as error:
                print("\n[ERROR] triage.saveRepro() @ copy repro (%s): %s\n" % (file, error))
                return FAILURE

        try:
            crash_files = glob.glob(settings.REPORT_CRASH_DIR + '/*')
        except Exception as error:
            print("\n[ERROR] triage.saveRepro() @ dir glob: %s\n" % error)
            return FAILURE

        crash_landing = settings.CRASH_DIR + os.sep + misc.getHash(repro) + '_' + os.path.basename(file)

        if(config.debug):
            print("copying ReportCrash file to %s\n" % crash_landing)

        for crash_file in crash_files:
            if(crash_file.endswith('.crash') and (os.path.basename(crash_file) not in config.report_list)):
                try:
                    shutil.copy(crash_file, crash_landing)
                except Exception as error:
                    print("\n[ERROR] triage.saveRepro() @ copy ReportCrash (%s): %s\n" % (crash_file, error))
                    return FAILURE

    #
    # copy over debugger logs
    #
    # note: for some reason, insulated debug logs may not show imcomplete crash info
    #
    if(config.attach or config.insulate):
        if(config.multibin):
            hash_info = hash_dir + \
                        os.sep + \
                        mode + \
                        '_' + \
                        target + \
                        '_' + \
                        config.host + \
                        '_' + \
                        str(config.port) + \
                        '.txt'
        else:
            hash_info = hash_out + '.txt'

        if(config.debug):
            print("copying debug logs %s -> %s\n" % (settings.FUZZ_INFO_STATIC, hash_info))

        try:
            shutil.copy(settings.FUZZ_INFO_STATIC, hash_info)
        except Exception as error:
            print("\n[ERROR] triage.saveRepro() @ copy debug log (%s): %s\n" % (settings.FUZZ_INFO, error))
            return FAILURE

    #
    # copy over standard remote server and client repros (single input, no sessions)
    #
    if(not(config.multibin or config.multistr)):
        if((config.mode == settings.CLIENT) or (config.mode == settings.SERVER)):
            hash_out = settings.CRASH_DIR + \
                       os.sep + \
                       mode + \
                       '_' + \
                       target + \
                       '_' + \
                       config.host + \
                       '_' + \
                       str(config.port) + \
                       '_' + \
                       misc.getHash(repro) + \
                       '.' + \
                       config.file_ext

            try:
                shutil.copy(file, hash_out)
            except Exception as error:
                print("\n[ERROR] triage.saveRepro() @ copy repro (%s): %s\n" % (file, error))
                return FAILURE

    return SUCCESS
