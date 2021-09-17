#!/usr/bin/python3 -Wignore
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# test_litefuzz.py
#
# py2> pytest
# py3> python3 -m pytest
#

import os
import sys
import shlex

import run
import mutator
import misc
import config
import settings
from settings import SUCCESS, FAILURE

### functional tests (quick) ###

#
# run.main()
#
def test_run_main():
    config.mode = settings.LOCAL

    if(misc.isWin32()):
        cmdline = 'C:\\Program Files (x86)\\GnuWin32\\bin\\true.exe'
    else:
        cmdline = 'true'

    cmdline = misc.setupCmdline(cmdline)

    config.maxtime = 2
    config.inputs = 'testing'
    config.iterations = 1

    if(not os.path.exists(config.inputs)):
        os.mkdir(config.inputs)

    with open(config.inputs + os.sep + 'test', 'w') as file:
        file.write('123')

    config.current_input = config.inputs + os.sep + 'test'

    misc.setupTmpRunDir()
    misc.setupNewIteration(cmdline)

    data = misc.readBytes(config.current_input)

    mutant = misc.getMutant(data)

    misc.writeBytes(settings.FUZZ_FILE, mutant)

    assert(run.main(cmdline) == SUCCESS)

#
# run.main() crash
#
def test_run_main_crash():
    config.mode = settings.LOCAL

    if(misc.isWin32()):
        plat = 'windows'
    elif(misc.isMac()):
        plat = 'mac'
    else:
        plat = 'linux'

    #
    # target will crash regardless of fuzz file
    #
    if(misc.isWin32()):
        cmdline = 'test\\' + plat + '\\a.exe --read FUZZ'
    else:
        cmdline = 'test/' + plat + '/a --read FUZZ'

    cmdline = misc.setupCmdline(cmdline)

    config.maxtime = 2
    config.inputs = 'testing'
    config.iterations = 1

    if(not os.path.exists(settings.CRASH_DIR)):
        os.mkdir(settings.CRASH_DIR)

    if(not os.path.exists(config.inputs)):
        os.mkdir(config.inputs)

    with open(config.inputs + os.sep + 'test', 'w') as file:
        file.write('123')

    config.current_input = config.inputs + os.sep + 'test'

    misc.setupTmpRunDir()
    misc.setupNewIteration(cmdline)

    data = misc.readBytes(config.current_input)

    mutant = misc.getMutant(data)

    misc.writeBytes(settings.FUZZ_FILE, mutant)

    assert(run.main(cmdline) == SUCCESS)

    #
    # assumes an initially clean crash directory
    #
    assert((len(config.pc_list) > 0 and len(os.listdir(settings.CRASH_DIR)) > 0) or config.dups == 1)

# net.main()
# net.main() crash
# core.repro()
# core.minimize()

### unit tests ###

#
# mutator.flip()
#
def test_mutator_flip():
    data = bytearray(b'test')
    size = len(data)

    mutant = mutator.flip(data, 1)

    assert(len(mutant) == size)

#
# mutator.highLow()
#
def test_mutator_highLow():
    data = bytearray(b'test')
    size = len(data)

    mutant = mutator.highLow(data)

    assert(len(mutant) == size)

#
# mutator.insert()
#
def test_mutator_insert():
    data = bytearray(b'test')
    size = len(data)

    mutant = mutator.insert(data)

    assert(len(mutant) > size)

#
# mutator.remove()
#
def test_mutator_remove():
    data = bytearray(b'test')
    size = len(data)

    mutant = mutator.remove(data)

    assert(len(mutant) < size)

#
# mutator.carve()
#
def test_mutator_carve():
    data = bytearray(b'test')
    size = len(data)

    mutant = mutator.carve(data)

    assert(len(mutant) < size)


#
# mutator.overwrite()
#
def test_mutator_overwrite():
    data = bytearray(b'test')
    size = len(data)

    mutant = mutator.overwrite(data)

    assert(len(mutant) == size)


#
# mutator.radamsa()
#
def test_mutator_radamsa():
    if(misc.isLinux() and (sys.version_info[0] >= 3)):
        data = bytearray(b'test')
        size = len(data)

        mutant = mutator.radamsa(data)

        assert(mutant != data)
    else:
        assert(1 == 1)


#
# misc.getWithin()
#
def test_misc_get_within():
    i = 10
    data_len = 100
    size = 50

    assert(misc.getWithin(i, data_len, size) < data_len)

#
# misc.getRandomInt()
#
def test_get_random_int():
    min = 0
    max = 100

    assert(misc.getRandomInt(min, max) <= max)

#
# misc.checkForExe()
#
def test_check_for_exe():
    if(misc.isWin32()):
        exe_one = 'C:\\Windows\\system32\\calc.exe'
        exe_two = 'not_true.exe'
    else:
        exe_one = 'true'
        exe_two = 'not_true'

    assert(misc.checkForExe(exe_one))
    assert(misc.checkForExe(exe_two) == False)
