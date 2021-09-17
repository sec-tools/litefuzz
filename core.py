#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# core.py
#
#

import os
import sys
import binascii
import glob
import re
import shutil
import signal
import socket
import ssl
import subprocess32 as subprocess
import time
from datetime import datetime
from time import time as timer
from tqdm import tqdm

import run
import net
import triage
import debug
import misc
import config
import settings
from settings import SUCCESS, FAILURE

#
# diff original and fuzzed files
#
def createDiff(original):
    if(config.debug):
        print("entering createDiff()\n")

    od_cmd = []

    if(misc.isUnix()):
        preexec_fn = os.setsid
    else:
        preexec_fn = None

    if(misc.isUnix()):
        #od_cmd = 'od -w1 -vAn -tx1 ' # mac's od may not support -w flag
        od_cmd.append('od')
    else:
        od_cmd.append(settings.OD_WIN_BIN)

    od_cmd.append('-vAn')
    od_cmd.append('-tx1')

    od_cmd.append(original)

    if(config.debug):
        print("%s\n" % od_cmd)

    #
    # write od output (part 1)
    #
    try:
        with open(settings.FUZZ_DIFF_ORIG, 'w') as file:
            process = subprocess.Popen(od_cmd,
                                    stdin=None,
                                    stdout=file,
                                    stderr=None,
                                    preexec_fn=preexec_fn)

            (output, error) = process.communicate(timeout=settings.TOOL_TIMEOUT)

            if(error):
                    print("\n[ERROR] '%s' @ pid=%d: %s\n" % (cmdline, process.pid(), error))
    except subprocess.TimeoutExpired as error:
        if(config.debug):
            print("%s\n" % error)

        misc.killProcess(process.pid)
    except Exception as error:
        print("\n[ERROR] core.diff @ run od orig: %s\n" % error)
        return FAILURE

    od_cmd.pop()
    od_cmd.append(settings.FUZZ_FILE)

    if(config.debug):
        print("%s\n" % od_cmd)

    #
    # write od output (part 2)
    #
    try:
        with open(settings.FUZZ_DIFF_FUZZ, 'w') as file:
            process = subprocess.Popen(od_cmd,
                                    stdin=None,
                                    stdout=file,
                                    stderr=None,
                                    preexec_fn=preexec_fn)

            (output, error) = process.communicate(timeout=settings.TOOL_TIMEOUT)

            if(error):
                print("\n[ERROR] '%s' @ pid=%d: %s\n" % (cmdline, process.pid(), error))
    except subprocess.TimeoutExpired as error:
        if(config.debug):
            print("%s\n" % error)

        misc.killProcess(process.pid)
    except Exception as error:
        print("\n[ERROR] core.diff @ run od fuzz: %s\n" % error)
        return FAILURE

    diff_cmd = []

    if(misc.isUnix()):
        diff_cmd.append('diff')
    else:
        diff_cmd.append(settings.DIFF_WIN_BIN)

    # with context
    # diff_cmd.append('-u')
    # diff_cmd.append('-b')
    # diff_cmd.append('-B')

    # without context
    diff_cmd.append('--changed-group-format=-%<+%>')
    diff_cmd.append('--unchanged-group-format=')

    diff_cmd.append(settings.FUZZ_DIFF_ORIG)
    diff_cmd.append(settings.FUZZ_DIFF_FUZZ)

    #
    # write diff output
    #
    try:
        with open(settings.FUZZ_DIFF, 'w') as file:
            process = subprocess.Popen(diff_cmd,
                                       stdin=None,
                                       stdout=file,
                                       stderr=None,
                                       preexec_fn=preexec_fn)
            (output, error) = process.communicate(timeout=settings.TOOL_TIMEOUT)

            if(error):
                print("\n[ERROR] '%s' @ pid=%d: %s\n" % (cmdline, process.pid(), error))
    except subprocess.TimeoutExpired as error:
        if(config.debug):
            print("%s\n" % error)

        misc.killProcess(process.pid)
    except Exception as error:
        print("\n[ERROR] core.diff @ run diff: %s\n" % error)
        return FAILURE

    #
    # try and create an analogous strings diff
    #
    if(createDiffString() != SUCCESS):
        return FAILURE

    return SUCCESS

#
# take the default binary diff file and produce a strings version
#
def createDiffString():
    if(config.debug):
        print("entering createDiffString()\n")

    try:
        with open(settings.FUZZ_DIFF, 'r') as file:
            bdiff = file.readlines()
    except Exception as error:
        print("\n[ERROR] core.createDiffString() @ read(FUZZ_DIFF): %s\n" % error)
        return FAILURE

    sdiff = []

    for line in bdiff:
        if(re.match('^(\s|\-|\+)(\s)', line)):
            sdiff.append(line)

    diff = []

    for line in sdiff:
        chars = line.split(' ')

        for (i, char) in enumerate(chars):
            if((char != '') and (re.match('(\s)(\-|\+)(\s)', char) == None)):
                try:
                    if(misc.isMac() or misc.isWin32()): # es especial
                        chars[i] = str(binascii.unhexlify(char))
                    else:
                        chars[i] = str(bytes.fromhex(char).decode('ascii'))
                except UnicodeDecodeError:
                    chars[i] = str('\\x' + chars[i].upper())
                    pass
                except Exception as error:
                    if(config.debug):
                        print("[INFO] core.createDiffString() exception: %s\n" % error)
                    continue

            #
            # add newline at the end
            #
            if(i == (len(chars) - 1)):
                chars[i] = chars[i] + '\n'

        diff.append(''.join(chars))

    diff = ''.join(diff)

    #
    # fix formatting
    #
    diffs = diff.splitlines()

    diff = ''

    for line in diffs:
        if(line.startswith('+')):
            line = line.replace('+', '+ ')

        if(line.startswith('-')):
            line = line.replace('-', '- ')

        diff += line + '\n'

    #
    # write diff strings edition (tm)
    #
    try:
        with open(settings.FUZZ_DIFF_STRING, 'w') as file:
            file.write(diff)
    except Exception as error:
        print("\n[ERROR] core.createDiffString() @ write(FUZZ_DIFF_STRING): %s\n" % error)
        return FAILURE

    return SUCCESS

#
# poor man's version of crash minimization (no external deps)
#
# idea: starting an index 0, remove each byte and check if it crashes
#
# - if it still crashes, keep the mutant and continue to the next byte
# - if it doesn't crash, restore the byte and continue to the next byte
#
# note: we're on with the target crashing on a different PC as long as it still
# crashes and keep all additional crashes as artifacts
#
# other notes
#
# - reuse the run dir and crash dir for all this
# - this type of minimization can act as a type of focused-fuzzing itself
# -- where you take an initial crash and you're minimizing it, but may also get more/new crashes
#
#
def minimize(file, cmdline, malloc, address):
    if(config.debug):
        print("entering minimize()")

    if(config.multibin or config.multistr):
        print("[ERROR] minimization isn't supported for session fuzzing\n")
        sys.exit(FAILURE)

    #
    # disable artifacts temporarily for crash repro and update crash dir
    #
    settings.ARTIFACTS_ENABLE = False

    if(file != config.current_input): # don't change crash dir for supermin mode
        settings.CRASH_DIR = settings.CRASH_DIR + '-min'

    if(config.insulate or (config.mode == settings.LOCAL_SERVER)):
        config.try_again = True

    #
    # only for local/client mode
    #
    if(misc.preChecks() == False):
        return FAILURE

    #
    # setup command line
    #
    org_cmdline = cmdline
    cmdline = misc.setupCmdline(cmdline)

    if(cmdline == None and (config.attach == None)):
        return FAILURE

    if(config.show_stats):
        misc.displayStats(org_cmdline, None, None, file)

    if(config.multibin):
        if(os.path.isdir(file) == False):
            print("[ERROR] %s is not a directory (multibin requires a directory of session files)\n" % file)
            return FAILURE
    else:
        if(os.path.isfile(file) == False):
            print("[ERROR] %s is not a file\n" % file)
            return FAILURE

    if(os.path.getsize(file) == 0):
        print("\n[ERROR] core.minimize() @ chosen input: %s is empty\n" % os.path.basename(file))
        return FAILURE

    if(reproCrash(file, cmdline, True) != SUCCESS):
        return FAILURE

    if(config.show_stats):
        print("[+] repro OK\n")
        print("[+] starting minimization\n")

    settings.ARTIFACTS_ENABLE = True # turn this back on to get artifacts for any new crashes

    #
    # "we are not yet in supermin mode" so save the original min filename to restore it as the final later
    #
    if(config.show_stats):
        settings.MIN_FILE_ORIG = settings.MIN_FILE

    #
    # swap the fuzz file used to repro the crash for the min file
    #
    if((config.mode != settings.CLIENT) and (config.mode != settings.SERVER)):
        for i, cmd in enumerate(cmdline):
            if(cmd == settings.FUZZ_FILE):
                cmdline[i] = settings.MIN_FILE

    settings.FUZZ_FILE = settings.MIN_FILE # for diffs from now on

    #
    # reset counters and cleanup files after test crash run
    #
    if(config.show_stats): # don't remove previous min's in supermin mode
        misc.cleanupMin()

    misc.resetCounters()

    data = misc.readBytes(file)

    if(data == None):
        return FAILURE

    min_temp = bytearray(len(data))
    min_data = bytearray()

    min_temp[:] = data

    config.min_original = len(data)

    pb = tqdm(total=0, bar_format="{desc}")

    if(config.debug):
        print("\n%s\n" % min_temp)

    #
    # starting at the first index, remove each byte
    #
    for i, b in enumerate(min_temp):
        if(config.debug):
            print("byte %d/%d -> %d\n" % (i, (len(data) - 1), b))

        #
        # make a copy of min_temp
        #
        min_data[:] = min_temp

        config.min_current = len(min_temp)

        #
        # remove byte at index
        #
        min_temp.pop(i)

        if(config.debug):
            print("\n%s\n" % min_temp)

        misc.writeBytes(settings.MIN_FILE, min_temp)

        if(config.debug):
            print("\nsettings.MIN_FILE len = %d\n" % len(min_temp))

        #
        # local app and client modes
        #
        if((config.mode == settings.LOCAL) or (config.mode == settings.LOCAL_CLIENT)):
            run.main(cmdline)
        #
        # local server mode
        #
        elif(config.mode == settings.LOCAL_SERVER):
            config.replay_file = settings.MIN_FILE

            net.replay(cmdline)

        else:
            print("[ERROR] minimization for remote targets is unsupported\n")
            return FAILURE

        #
        # helps to fuzz interactive client GUIs such
        # as filezilla, maybe even web browsers, etc
        #
        if(config.key != None):
            misc.hitKey()

        misc.copyDebugOutput()

        #
        # check for crashes from debugger output
        #
        if((config.insulate) or (config.mode == settings.LOCAL_SERVER)):
            if(misc.isUnix()):
                triage.checkDebugger(cmdline)

        config.count = i # for min, we use it for current index
        config.iterations += 1

        #
        # show progress
        #
        if(i == (len(min_temp) - 1)):
            misc.displayCount(pb, len(min_temp), False) # hm, strange but works
        else:
            misc.displayCount(pb, (len(min_temp) + 1), False) # since we pop'd one off, account for that

        if(config.debug):
            print("\nmin_temp=%d, min_data=%d\n" % (len(min_temp), len(min_data)))

        min_temp = minCrashAnalysis(min_temp, min_data, i, 1)

        config.crash = False
        config.duplicate = False

    misc.writeBytes(settings.MIN_FILE, min_data)

    if(config.debug):
        print("\nwrote min to %s\n" % settings.MIN_FILE)

    pb.close()

    if(len(min_data) == 0):
        print("\n[-] minimization reduced crasher to zero bytes, something probably went wrong")
    elif(len(min_data) == len(data)):
        if(config.supermin and (settings.MIN_FILE != settings.MIN_FILE_ORIG)): # we went past the first round
            print("\n[+] achieved maximum minimization @ %d bytes (%s)" % (len(min_data), os.path.basename(settings.MIN_FILE_ORIG)))
        else:
            print("\n[~] minimization did not reduce crasher file, perhaps the target really needs all these bytes...")

        config.min_hit = True

        if(config.supermin):
            #
            # move final min file to original min filename and remove previous min files
            #
            try:
                shutil.move(os.path.abspath(settings.MIN_FILE), os.path.abspath(settings.MIN_FILE_ORIG))
            except Exception as error:
                print("\n[ERROR] core.minimize() @ supermin final move: %s\n" % error)
                return FAILURE

            for name in os.listdir(settings.CRASH_DIR):
                if(('.min' in name) and (name not in os.path.basename(settings.MIN_FILE_ORIG))):
                    try:
                        os.remove(settings.CRASH_DIR + os.sep + name)
                    except Exception as error:
                        print("\n[ERROR] couldn't remove other min files: %s\n" % error)
                        return FAILURE

            settings.MIN_FILE = settings.MIN_FILE_ORIG
            settings.FUZZ_FILE = settings.MIN_FILE_ORIG # repro
    else:
        if(config.min_pc == config.current_pc): # last pc, the one that min file crashes
            if(config.supermin): # don't show min file iteration filenames in supermin mode
                print("\n[+] reduced crash @ pc=%s to %d bytes\n" % (config.min_pc, len(min_data)))
            else:
                print("\n[+] reduced crash @ pc=%s to %d bytes (%s)" % (config.min_pc,
                                                                        len(min_data),
                                                                        os.path.basename(settings.MIN_FILE)))
        else:
            if(config.supermin):
                print("\n[+] reduced crash @ pc=%s -> pc=%s to %d bytes\n" % (config.min_pc,
                                                                              config.current_pc,
                                                                              len(min_data)))
            else:
                print("\n[+] reduced crash @ pc=%s -> pc=%s to %d bytes (%s)" % (config.min_pc,
                                                                                 config.current_pc,
                                                                                 len(min_data),
                                                                                 os.path.basename(settings.MIN_FILE)))

            config.min_pc = config.current_pc # now make the current pc the new min pc

    if(config.debug):
        print("\n[INFO] replaying min file for crash artifacts")

    if(reproCrash(settings.MIN_FILE, cmdline, False) != SUCCESS):
        return FAILURE

    return SUCCESS

#
# check minimized crash
#
# if no crash, restore copy with orginial byte
#
# if crash, check if its the same PC as crash during repro
# -> if so, don't restore byte
# -> if not, restore byte because its a new crash (we're trying to minimize based on PC)
#
def minCrashAnalysis(min_temp, min_data, i, mode):
    if((config.crash == False) and (config.duplicate == False)):
        if(config.debug):
            if(mode == 1):
                print("\n[INFO] no crash after removing byte=%d @ index=%d, treating byte as importante\n" % (min_data[i], i))

            if(mode == 2):
                print("\n[INFO] no crash after removing bytes=(%d, %d) @ indices=(%d, %d), treating bytes as importante\n" % (min_data[i],
                                                                                                                              min_data[i + 1],
                                                                                                                              i,
                                                                                                                              (i + 1)))

            if(mode == 4):
                print("\n[INFO] no crash after removing bytes=(%d, %d, %d, %d) @ indices=(%d, %d, %d, %d), treating bytes as importante\n" % (min_data[i],
                                                                                                                                              min_data[i + 1],
                                                                                                                                              min_data[i + 2],
                                                                                                                                              min_data[i + 3],
                                                                                                                                              i,
                                                                                                                                              (i + 1),
                                                                                                                                              (i + 2),
                                                                                                                                              (i + 3)))

        min_temp[:] = min_data
    else:
        if(config.debug):
            print("\ncurrent_pc=%s, min_pc=%s\n" % (config.current_pc, config.min_pc))

        #
        # handle a few conditions here
        #
        # - current_pc = min_pc (crash pc), remove the byte to minimize
        # - current_pc is similar to min_pc, then they may be the same crash at different PCs
        # - current_pc = wild and min_pc = wild, then they are likely the same crash at different wild PCs
        # -- eg. jmp rdx and rdx is some crazy big value like 0x7755ABCD19192020
        # - neither of those, this is a new crash and therefore keep the byte and don't minimize for it
        #
        if(config.current_pc == config.min_pc):
            if(config.debug):
                print("\n[INFO] target still crashed with PC=%s after removing byte=%d @ index=%d\n" % (config.current_pc, min_data[i], i))
        elif(misc.isSimilar(config.min_pc, config.current_pc)):
            if(config.debug):
                print("\n[INFO] target crashed with new PC=%s vs original=%s, assuming same crash after removing byte=%d @ index=%d\n" % (config.current_pc, config.min_pc, min_data[i], i))
        elif(misc.isWild(config.current_pc) and misc.isWild(config.min_pc)):
            if(config.debug):
                print("\n[INFO] target crashed with new wild PC=%s vs wild original=%s, assuming same crash after removing byte=%d @ index=%d\n" % (config.current_pc, config.min_pc, min_data[i], i))
        elif((config.current_pc == 'UNKNOWN') or (config.min_pc == 'UNKNOWN')):
            if(config.debug):
                print("\n[INFO] target crashed but either PC=UNKNOWN or original PC=UNKNOWN, minimization may not work properly")
        else:
            if(config.debug):
                print("\n[INFO] target crashed with new PC=%s after removing byte=%d @ index=%d, byte will be restored\n" % (config.current_pc, min_data[i], i))

                min_temp[:] = min_data

    return min_temp

#
# replay a crashing file against a target
#
def repro(file, cmdline, malloc, address):
    if(config.debug):
        print("entering repro()")

    if(config.insulate):
        print("[ERROR] repro mode for insulated apps is not supported\n")
        return FAILURE

    #
    # slight tweak
    #
    settings.DIFF_ENABLE = False

    if any([config.insulate or (config.mode == settings.SERVER) or (config.mode == settings.LOCAL_SERVER)]):
        config.try_again = True

    #
    # only for local mode
    #
    if(cmdline != None):
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

    if(config.show_stats):
        misc.displayStats(org_cmdline, None, None, file)

    if(config.multibin):
        if(os.path.isdir(file) == False):
            print("[ERROR] %s is not a directory (multibin requires a directory of session files)\n" % file)
            return FAILURE
    else:
        if(os.path.isfile(file) == False):
            print("[ERROR] %s is not a file\n" % file)
            return FAILURE

    if(os.path.getsize(file) == 0):
        print("\n[ERROR] core.repro() @ chosen input: %s is empty\n" % os.path.basename(file))
        return FAILURE

    if(reproCrash(file, cmdline, True) != SUCCESS):
        return FAILURE

    if(config.repro):
        if(config.dups > 0):
            config.crash = True

        if(config.repro):
            config.dups = config.crashes

    return SUCCESS

#
# core repro
#
def reproCrash(file, cmdline, banner):
    if(config.debug):
        print("entering reproCrash()\n")

    if(config.insulate):
        if(config.debug):
            print("[INFO] repro for insulated targets is unsupported\n")
            return FAILURE

    if(banner and config.show_stats):
        print("[+] attempting to repro the crash...")

    #
    # set it up for minimization or repro runs
    #
    if(config.min or config.repro):
        config.current_input = os.path.abspath(file)

        files = None

        if(config.multibin):
            try:
                files = glob.glob(file + '/*') # file is actually a repro directory here
            except Exception as error:
                print("[ERROR] core.reproCrash() @ glob: %s\n" % error)
                return FAILURE

        data = None

        if(config.multistr):
            data = misc.readBytes(file)

            if(data == None):
                print("[ERROR] core.reproCrash() @ reading the repro '%s': failed\n" % file)
                return FAILURE

        if(config.multibin or config.multistr):
            if(misc.setupSession(files, data) != SUCCESS):
                return FAILURE

        if(misc.setupNewIteration(cmdline) != SUCCESS):
            return FAILURE

    #
    # don't setup new iteration during repro for debugger-ran apps
    #
    if((config.insulate == False) and (config.mode != settings.LOCAL_SERVER)):
        if(misc.setupNewIteration(cmdline) != SUCCESS):
            return FAILURE

    #
    # don't increment count here during minimization
    #
    if(config.repro):
        config.count += 1

    #
    # fix the crash repro file for supermin mode
    #
    if(config.supermin and config.min_hit):
        for (i, cmd) in enumerate(cmdline):
            if('.min' in cmd):
                cmdline[i] = file

    if(config.mode == settings.LOCAL):
        if(config.debug):
            print("\nreproing a local app target\n")

        if(config.insulate):
            if(config.debug):
                print("\n[INFO] reproing crashes with insulated apps is experimental and has not been tested")

            if(debug.main(cmdline) != SUCCESS):
                print("\n[ERROR] failed to run cmdline in debugger\n")
                return FAILURE

            misc.doInsulate()
        else:
            if(run.main(cmdline) != SUCCESS):
                print("\n[ERROR] failed to run cmdline\n")
                return FAILURE

            if((cmdline != None) and (config.process != None)):
                misc.checkForCrash(cmdline)
    else:
        if(config.debug):
            print("\nreproing a local or remote network target\n")

        if(config.address != None):
            misc.setupAddress()

            if(None in (config.prot, config.host, config.port)):
                if(config.debug):
                    print("\n[ERROR] target address should be in proto://host:port format: %s\n" % config.address)
                return FAILURE

            if((misc.checkIPAddress(config.host) == False) and (misc.checkHostname(config.host) == False)):
                if(config.debug):
                    print("\n[ERROR] invalid ip or hostname: %s\n" % config.host)
                return FAILURE

            if(config.mode == settings.SERVER):
                if(misc.checkPort(config.prot, config.host, config.port) == False):
                    if(config.repro):
                        print("\n[ERROR] core.reproCrash @ connection failed to %s\n" % config.address)

                    return FAILURE

        if(config.insulate):
            debug.main(cmdline)

            misc.doInsulate()
        else:
            config.replay_file = file

            net.replay(cmdline)

    #
    # helps to fuzz interactive client GUIs such
    # as filezilla, maybe even web browsers, etc
    #
    if(config.key != None):
        misc.hitKey()

    #
    # only copy debug output during fuzzing
    #
    if((config.min == False) and (config.repro == False)):
        if(misc.copyDebugOutput() != SUCCESS):
            print("\n[ERROR] core.reproCrash() @ copyDebugOutput() failed\n")

    #
    # check for crashes from debugger output
    #
    if((config.insulate) or (config.mode == settings.LOCAL_SERVER)):
        if(misc.isUnix()):
            if(triage.checkDebugger(cmdline) != SUCCESS):
                if(config.debug):
                    print("\n[INFO] core.repro() no crash in debugger\n")

    #
    # during local app runs, config.crash gets set during triage
    #
    # note: for insulated or local server apps, we check them twice just in case of timing issues
    #
    if((config.mode == settings.CLIENT) or (config.mode == settings.SERVER)):
        if(config.repro):
            if(config.mode == settings.CLIENT):
                print("OK, check to see if remote client crashed\n")
            else:
                if(misc.checkPort(config.prot, config.host, config.port) == False):
                    misc.newCrash()
                elif(config.attach != None):
                    if(misc.checkReportCrash()):
                        misc.newCrash()
                else:
                    print("\n[!] target server still seems to be up")
        else:
            config.replay_file = file

            if(config.mode == settings.CLIENT):
                if(net.replay(cmdline) != SUCCESS):
                    misc.newCrash()

                    #
                    # stop fuzzing only if we're not doing any local/remote hybrid stuff
                    #
                    if((config.attach == None) and (config.report_crash == False)):
                        config.down = True

                    if(config.multibin):
                        repro = None # falls back to using config.session in saveRepro()
                    else:
                        repro = file

                    return triage.saveRepro(repro)

            #
            # if the full replay process fails, double check by trying to connect to the server
            #
            if(config.mode == settings.SERVER):
                if(net.replay(cmdline) != SUCCESS):
                    if(misc.checkPort(config.prot, config.host, config.port) == False):
                        misc.newCrash()

                        if((config.attach == None) and (config.report_crash == False)):
                            config.down = True

                        if(config.multibin):
                            repro = None # falls back to using config.session in saveRepro()
                        else:
                            repro = file

                        return triage.saveRepro(file)
    else:
        if((config.crash == False) and (config.duplicate == False)):
            if(config.insulate or (config.mode == settings.LOCAL_SERVER)):
                if(config.try_again):
                    config.try_again = False

                    if(config.debug):
                        print("target didn't crash, waiting for %f seconds and trying again...\n" % (config.maxtime / 2))

                    time.sleep((config.maxtime / 2))

                    reproCrash(file, cmdline, False)
            else:
                print("\n[ERROR] target did not crash -- check cmdline, minfile and malloc debug options OR increase maxtime\n")
                # return FAILURE
                sys.exit(FAILURE)
        else:
            if(config.debug):
                if(len(config.pc_list) > 0):
                    print("\n[INFO] target crashed @ pc=%s\n" % config.current_pc)
                else:
                    print("\n[INFO] target crashed (dup)\n")

    return SUCCESS
