#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# settings.py
#
#

import os
import sys
import warnings
warnings.filterwarnings("ignore")

import config

#
# status
#
SUCCESS = 0
FAILURE = 1

#
# runtime config
#
if(str(sys.platform).startswith('linux') or
   str(sys.platform).startswith('darwin')):
    TMP_DIR = '/tmp/litefuzz'
if(str(sys.platform).startswith('win32')):
    TMP_DIR = 'C:\\Windows\\Temp\\litefuzz'

RUN_DIR = TMP_DIR # this gets set for each fuzzing session's unique run dir

CRASH_DIR = 'crashes'
CHECK_DUPS_PREV_RUN = True
TIMEOUT = 10

#
# primary modes
#
LOCAL  = 1
LOCAL_CLIENT = 2
LOCAL_SERVER = 3
CLIENT = 4
SERVER = 5

#
# set based on TMP_DIR and the generated per-run id
#
FUZZ_FILE = None
FUZZ_FILE_PREV = None
FUZZ_OUTPUT = None
FUZZ_INFO = None
FUZZ_INFO_STATIC = None
FUZZ_DIFF = None
FUZZ_DIFF_STRING = None
FUZZ_DIFF_ORIG = None
FUZZ_DIFF_FUZZ = None
FUZZ_OUTPUT_DEBUG = None
FUZZ_OUTPUTS_DEBUG = None

MIN_FILE = None
MIN_FILE_ORIG = None

RUN_ID_MIN = 1000
RUN_ID_MAX = 9999

#
# mutators
#
MUTATOR_CHOICE = 0 # random

if((str(sys.platform).startswith('linux')) and (sys.version_info[0] >= 3)):
    MUTATOR_MAX = 7 # pyradamsa is linux only
else:
    MUTATOR_MAX = 6

FLIP_MUTATOR = 1
HIGHLOW_MUTATOR = 2
INSERT_MUTATOR = 3
REMOVE_MUTATOR = 4
CARVE_MUTATOR = 5
OVERWRITE_MUTATOR = 6
RADAMSA_MUTATOR = 7

FLIP_MUTATOR_ENABLE = True
HIGHLOW_MUTATOR_ENABLE = True
INSERT_MUTATOR_ENABLE = True
REMOVE_MUTATOR_ENABLE = True
CARVE_MUTATOR_ENABLE = True
OVERWRITE_MUTATOR_ENABLE = True
RADAMSA_MUTATOR_ENABLE = True

# number of random bytes to flip for each mutated test case (simple mutator)
MUTATION_MIN = 1
MUTATION_MAX = 8

# insert mutator
SIZE_MIN = 1
SIZE_MAX = 5000

#
# unix crash codes
#
SIGTRAP = -5
SIGABRT = -6
SIGILL  = -7
SIGFPE  = -8
SIGSEGV = -11

#
# golang
#
SIGGO = 2

EXCEPTIONS = {
                'EXC_BREAKPOINT' : SIGTRAP,
                'EXC_ARITHMETIC' : SIGFPE,
                'EXC_BAD_INSTRUCTION' : SIGILL,
                'EXC_BAD_ACCESS' : SIGSEGV,
                'SIGTRAP' : SIGTRAP,
                'SIGABRT' : SIGABRT,
                'SIGFPE' : SIGFPE,
                'SIGILL' : SIGILL,
                'SIGSEGV' : SIGSEGV
}

# misc
ARTIFACTS_ENABLE = True
DIFF_ENABLE = True
KEEPAWAKE_ENABLE = True
KILL_EXISTING_PROCESS = True

# timeouts
INSULATE_TIMEOUT = 30
EXEC_TIMEOUT = 3
TOOL_TIMEOUT = 5
DEBUG_TIMEOUT_MULTIPLE = 10
NETWORK_TIMEOUT_MULTIPLE = 2
CLIENT_TIMEOUT = 10
LOCAL_SERVER_TIMEOUT = 5

if(str(sys.platform).startswith('win32')):
    null = 'NUL'
else:
    null = '/dev/null'

# mac
KYA_BIN = '/Applications/KeepingYouAwake.app/Contents/MacOS/KeepingYouAwake'
KYA_NAME = 'KeepingYouAwake'

REPORT_CRASH_NAME = 'ReportCrash'
# REPORT_CRASH_DIR = os.environ["HOME"] + '/Library/Logs/DiagnosticReports'
REPORT_CRASH_DIR = '/Library/Logs/DiagnosticReports'
REPORT_CRASH_DIR_OLD = REPORT_CRASH_DIR + os.sep + 'OLD'
REPORT_CRASH_LOAD = 'sudo launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist'
# REPORT_CRASH_LOAD_ROOT = 'sudo launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.Root.plist'

# windows
DIFF_WIN_BIN = 'C:\\ProgramData\\chocolatey\\lib\\diffutils\\tools\\bin\\diff.exe'
OD_WIN_BIN = 'C:\\Program Files (x86)\\GnuWin32\\bin\\od.exe'

CONSOLE_DEBUGGER_PATH = 'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe'
MEMORY_DUMP_REG_KEY = 'SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\'

MEMORY_DUMP = False

# malloc helpers
LIBEFENCE_PATH  = '/usr/lib/libefence.so'
LIBGMALLOC_PATH = '/usr/lib/libgmalloc.dylib'

GLIBC_MALLOC_CHECK = 'MALLOC_CHECK_=3'

DEBUG_DISSASSEMBLE_LLDB = 'dis -s $pc-32 -c 24 -m -F intel'

DEBUG_ENV_EFENCE_GLIBC_ENABLE = False # main
DEBUG_ENV_EFENCE_ENABLE = False
DEBUG_ENV_GLIBC_ENABLE = False

DEBUG_ENV_EFENCE = dict(os.environ, LD_PRELOAD=LIBEFENCE_PATH)
DEBUG_ENV_GLIBC = dict(os.environ, MALLOC_CHECK_='3') # fallback

DEBUG_ENV_GMALLOC_ENABLE = False
DEBUG_ENV_GMALLOC = dict(os.environ, DYLD_INSERT_LIBRARIES=LIBGMALLOC_PATH)

DEBUG_ENV_PAGEHEAP_ENABLE = False
DEBUG_ENV_PAGEHEAP_DISABLE = False
DEBUG_ENV_GFLAG_MAGIC = '0x02000000'
DEBUG_ENV_PAGEHEAP_MAGIC = '0x3'

GFLAGS_BIN_PATH = 'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\gflags.exe'
PAGEHEAP_REG_KEY = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\'

USER_VA_MAX = '0x7fffffffffff'
SIMILAR_PC_RANGE = '0x1000'

#
# defaults
#
ITERATIONS_DEFAULT = 1
MAX_AVG_EXEC = 100
MAX_TIME_DEFAULT = 1
BIG_INPUT_SIZE = 1000000 # 1mb
MAX_INPUT_SIZE = 10000000 # 10mb limit
NET_SLEEP_TIME = 20
SEND_RECV_TIME = 0.1

#
# network
#
RECV_SIZE = 4096
TCP_BACKLOG = 5
TLS_DIR = 'tls' + os.sep
TEST_DATA = b'test'
NETWORK_CRT = TLS_DIR + 'network.crt'
NETWORK_KEY = TLS_DIR + 'network.pem'
GENERATE_CERT_CMD = 'openssl req -x509 -new -nodes -subj \'/O=o/C=CC/CN=NC\' -keyout ' + NETWORK_KEY + ' -out ' + NETWORK_CRT + ' -days 5555'
SEND_TEST_PACKET = False
TCP_KEEP_GOING = True
