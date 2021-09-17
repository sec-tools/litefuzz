#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# cli.py
#
#

import sys
import argparse

import settings

#
# parse and return command line arguments
#
def arg_parse():
    parser = argparse.ArgumentParser()

    parser.add_argument("-l",
                        "--local",
                        default=False,
                        action="store_true",
                        help="target will be executed locally")

    parser.add_argument("-k",
                        "--client",
                        default=False,
                        action="store_true",
                        help="target a network client")

    parser.add_argument("-s",
                        "--server",
                        default=False,
                        action="store_true",
                        help="target a network server")

    parser.add_argument("-c",
                        "--cmdline",
                        type=str,
                        help="target command line")

    parser.add_argument("-i",
                        "--inputs",
                        type=str,
                        help="input directory or file")

    parser.add_argument("-n",
                        "--iterations",
                        type=int,
                        default=settings.ITERATIONS_DEFAULT,
                        help="number of fuzzing iterations (default: %d)" % settings.ITERATIONS_DEFAULT)

    parser.add_argument("-x",
                        "--maxtime",
                        type=float,
                        default=settings.MAX_TIME_DEFAULT,
                        help="timeout for the run (default: %d)" % settings.MAX_TIME_DEFAULT)

    parser.add_argument("--mutator",
                        "--mutator",
                        type=int,
                        default=settings.MUTATOR_CHOICE,
                        help="timeout for the run (default: %d=random)" % settings.MUTATOR_CHOICE)

    parser.add_argument("-a",
                        "--address",
                        type=str,
                        help="server address in the ip:port format")

    parser.add_argument("-o",
                        "--crashdir",
                        type=str,
                        help="specify the directory to output crashes (default: crashes)")

    parser.add_argument("-t",
                        "--tempdir",
                        type=str,
                        help="specify the directory to output runtime fuzzing artifacts (default: OS tmp + run dir)")

    parser.add_argument("-f",
                        "--fuzzfile",
                        type=str,
                        help="specify the path and filename to place the fuzzed file (default: OS tmp + run dir + fuzz_random.ext)")

    parser.add_argument("-m",
                        "--minfile",
                        type=str,
                        help="specify a crashing file to generate a minimized version of it (bonus: may also find variant bugs)")

    parser.add_argument("-mm",
                        "--supermin",
                        type=str,
                        help="loops minimize to grind on until no more bytes can be removed")

    parser.add_argument("-r",
                        "--reprofile",
                        type=str,
                        help="specify a crashing file or directory to replay on the target")

    parser.add_argument("-e",
                        "--reuse",
                        default=False,
                        action="store_true",
                        help="enable second round fuzzing where any crashes found are reused as inputs")

    parser.add_argument("-p",
                        "--multibin",
                        default=False,
                        action="store_true",
                        help="use multiple requests or responses as inputs for fuzzing simple binary network sessions")

    parser.add_argument("-pp",
                        "--multistr",
                        default=False,
                        action="store_true",
                        help="use multiple requests or responses within input for fuzzing simple string-based network sessions")

    parser.add_argument("-u",
                        "--insulate",
                        default=False,
                        action="store_true",
                        help="only execute the target once and inside a debugger (eg. interactive clients)")

    parser.add_argument("--nofuzz",
                        "--nofuzz",
                        default=False,
                        action="store_true",
                        help="send input as-is without mutation (useful for debugging)")

    parser.add_argument("--key",
                        "--key",
                        type=str,
                        help="send a particular key every iteration for interactive targets (eg. F5 for refresh)")

    parser.add_argument("--click",
                        "--click",
                        default=False,
                        action="store_true",
                        help="click the mouse (eg. position the cursor over target button to click beforehand)")

    parser.add_argument("--tls",
                        "--tls",
                        default=False,
                        action="store_true",
                        help="enable TLS for network fuzzing")

    parser.add_argument("--golang",
                        "--golang",
                        default=False,
                        action="store_true",
                        help="enable fuzzing of Golang binaries")

    parser.add_argument("--attach",
                        "--attach",
                        type=str,
                        help="attach to a local server process name (mac only)")

    parser.add_argument("--cmd",
                        "--cmd",
                        type=str,
                        help="execute this command after each fuzzing iteration (eg. umount /Volumes/test.dir)")

    parser.add_argument("--rmfile",
                        "--rmfile",
                        type=str,
                        help="remove this file after every fuzzing iteration (eg. target won't overwrite output file)")

    parser.add_argument("--reportcrash",
                        "--reportcrash",
                        type=str,
                        help="use ReportCrash to help catch crashes for a specified process name (mac only)")

    parser.add_argument("--memdump",
                        "--memdump",
                        default=False,
                        action="store_true",
                        help="enable memory dumps (win32)")

    parser.add_argument("--nomemdump",
                        "--nomemdump",
                        default=False,
                        action="store_true",
                        help="disable memory dumps (win32)")

    parser.add_argument("-z",
                        "--malloc",
                        type=str,
                        nargs='?',
                        const='default',
                        help="enable malloc debug helpers (free bugs, but perf cost)")

    parser.add_argument("-zz",
                        "--nomalloc",
                        default=False,
                        action="store_true",
                        help="disable malloc debug helpers (eg. pageheap)")

    parser.add_argument("-d",
                        "--debug",
                        default=False,
                        action="store_true",
                        help="Turn on debug statements")

    args = parser.parse_args()

    if(len(sys.argv) == 1):
        parser.print_help()
        parser.exit()

    return args
