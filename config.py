#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# config.py
#
#

import signal

# main
address = None
attach = None
dbg32 = None
debug = False
cmd = None
count = 0
current_input = None
env = None
exec_avg = 0
exec_times = []
fuzz = False
golang = False
inputs = None
insulate = False
insulate_pid = None
key = None
kill_proc = None
iterations = 0
maxtime = 0
min = False
min_current = 0
min_original = 0
min_pc = None
min_hit = False
supermin = False
memdump_pid = None
multibin = False
multistr = False
mode = 0
nofuzz = False
pb = None
process = None
report_crash = False
report_list = []
repro = False
returncode = None
reusedir = None
rmfile = None
rmtemp = True
run_id = 0
session = []
session_prev = []
show_stats = True
static_fuzz_file = None
target = None
try_again = False

# crash
crash = False
duplicate = False
crashes = 0
dups = 0
current_pc = None
pc_list = []

# network
broken_pipe = False
conn = None
sock = None
context = None
cli_conn = None
down = False
prot = None
host = None
port = None
replay_file = None
cert = None
tls = False
triage = False

# files
crash_file = ''
file_ext = ''

# pause/resume
org_sigint = signal.getsignal(signal.SIGINT)
