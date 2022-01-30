# litefuzz

A multi-platform fuzzer for poking at userland binaries and servers

- [litefuzz](#litefuzz)
  - [intro](#intro)
  - [why](#why)
  - [how it works](#how-it-works)
    - [what it does](#what-it-does)
    - [what it doesn't do](#what-it-doesnt-do)
  - [support](#support)
    - [python versions](#python-versions)
    - [linux](#linux)
    - [mac](#mac)
    - [windows](#windows)
    - [targets](#targets)
    - [triage](#triage)
  - [getting started](#getting-started)
    - [tests](#tests)
      - [unit tests](#unit-tests)
      - [crashing app tests](#crashing-app-tests)
  - [options](#options)
    - [crash directory](#crash-directory)
    - [insulate mode](#insulate-mode)
    - [timeout](#timeout)
    - [mutators](#mutators)
    - [ReportCrash](#reportcrash)
    - [pause](#pause)
    - [reusing crashes for variant finding](#reusing-crashes-for-variant-finding)
    - [memory debugging helpers](#memory-debugging-helpers)
    - [checking live target output](#checking-live-target-output)
    - [client and server modes](#client-and-server-modes)
    - [local network examples](#local-network-examples)
    - [remote network examples](#remote-network-examples)
      - [client](#client)
      - [server](#server)
        - [TLS](#tls)
      - [multiple data exchange modes](#multiple-data-exchange-modes)
    - [attaching to a process](#attaching-to-a-process)
    - [crash artifacts](#crash-artifacts)
    - [golang](#golang)
    - [repros](#repros)
    - [remove file](#remove-file)
    - [minimization](#minimization)
    - [command](#command)
  - [examples](#examples)
    - [local app](#local-app)
      - [quick look](#quick-look)
      - [enumerating file handlers on Ubuntu](#enumerating-file-handlers-on-ubuntu)
      - [enumerating file handlers on OS X](#enumerating-file-handlers-on-os-x)
    - [client](#client-1)
      - [quick look](#quick-look-1)
      - [local client](#local-client)
      - [remote client](#remote-client)
    - [server](#server-1)
      - [quick look](#quick-look-2)
      - [local server](#local-server)
      - [remote server](#remote-server)
- [command line](#command-line)
- [trophies](#trophies)
- [FAQ](#faq)
  - [how did this project come about?](#how-did-this-project-come-about)
  - [is this project actively maintained?](#is-this-project-actively-maintained)
  - [how do you know the fuzzer is working well and did you measure it against others?](#how-do-you-know-the-fuzzer-is-working-well-and-did-you-measure-it-against-others)
  - [what would you change if you were to re-write it today?](#what-would-you-change-if-you-were-to-re-write-it-today)
  - [how stable is litefuzz?](#how-stable-is-litefuzz)
  - [are there unsupported scenarios for litefuzz?](#are-there-unsupported-scenarios-for-litefuzz)
  - [what guarentees are given for this project or it's code?](#what-guarentees-are-given-for-this-project-or-its-code)
  - [author / references](#author--references)

## intro

Litefuzz is meant to serve a purpose: fuzz and triage on all the major platforms, support both CLI/GUI apps, network clients and servers in order to find security-related bugs. It simplifies the process and makes it easy to discover security bugs in many different targets, across platforms, while just making a few honest trade-offs.

It isn't built for speed, scalability or meant to win any prizes in academia. It applies simple techniques at various angles to yield results. For console-based file fuzzing, you should probably just use [AFL](https://lcamtuf.coredump.cx/afl/). It has superior performance, instrumention capabilities (and faster non-instrumented execs), scale and can make freakin' jpegs out of [thin air](https://web.archive.org/web/20210118070714/http://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html). For networking fuzzing, the [mutiny fuzzer](https://github.com/Cisco-Talos/mutiny-fuzzer) also works well if you have PCAPs to replay and [frizzer](https://github.com/demantz/frizzer) looks promising as well. But if you want to give this one a try, it can fuzz those kinds of targets across platforms with just a single tool.

./ and give your target... a lite fuzz.

```
$ sudo apt install latex2rtf

$ ./litefuzz.py -l -c "latex2rtf FUZZ" -i input/tex -o crashes/latex2rtf -n 1000 -z
--========================--
--======| litefuzz |======--
--========================--

[STATS]
run id:     3516
cmdline:    latex2rtf FUZZ
crash dir:  crashes/latex2rtf
input dir:  input/tex
inputs:     1
iterations: 1000
mutator:    random(mutators)

@ 1000/1000 (3 crashes, 127 duplicates, ~0:00:00 remaining)

[RESULTS]
> completed (1000) iterations with (3) unique crashes and 127 dups
>> check crashes/latex2rtf for more details
```

This is a simple local target which AFL++ is perfectly capable of handling and just quickly given as an example. Litefuzz was designed to do much more in the way of network and GUI fuzzing which you'll see once you dive in.

## why

Yes, another fuzzer and one that doesn't track all that well with the current trends and conventions. Trade-offs were made to address certain requirements. These requirements being a fuzzer that works by default on multiple platforms, fuzzes both local and network targets and is very easy to use. Not trying to convince anybody of anything, but let's provide some context. Some targets require a lot of effort to integrate fuzzers such as AFL into the build chain. This is not a problem as this fuzzer does not require instrumentation, sacraficing the precise coverage gained by instrumentation for ease and portability. AFL also doesn't support network fuzzing out of the box, and while there are projects based on it that do, they are far from straightforward to use and usually require more code modifications and harnesses to work (similar story with [Libfuzzer](https://llvm.org/docs/LibFuzzer.html)). It doesn't do parallel fuzzing, nor support anything like the blazing speed improvments that [persistent mode](https://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html) can provide, so it cannot scale anywhere close to what fuzzers with such capabilities. Again, this is not a state-of-the-art fuzzer. But it doesn't require source code, properly up a build or certain OS features. It can even fuzz some network client GUIs and interactive apps. It lives off the land in a lot of ways and many of the features such as mutators and minimization were just written from scratch.

It was designed to "just work" and effort has been put into automating the setup and installation for the few dependencies it needs. This fuzzer was written to serve a purpose, to provide value in a lot of different target scenarios and environments and most importantly and for what all fuzzers should ultimately be judged on: the ability to find bugs. And **it does find** [bugs](https://github.com/sec-tools/beta/blob/main/README.md#trophies). It doesn't presume there is target source code, so it can cover closed source software fairly well. It can run as part of automation with little modification, but is geared towards being fun to use for vulnerability researchers. It is however more helpful to think of it as a R&D project rather than a fully-fledged product. Also, there's no complicated setup where it's slightly broken out of the box or needs more work to get it running on modern operating systems. It's been tested working on Ubuntu Linux 20.04, Mac OS 11 and Windows 10 and comes with fully functional scripts that do just about everything for you in order to setup a ready-to-fuzz environment.

**Once the setup script completes, it only takes a few minutes to get started fuzzing a ton of different targets.**

## how it works

Litefuzz supports three different modes: local, client and server. Local means targeting local binaries, which on Linux/Mac are launched via subprocess with automatic GDB and LLDB triage support respectively on crashes and via [WinAppDbg](https://github.com/MarioVilas/winappdbg) on Windows. Crashes are written to a local crash directory and sorted by fault type, such as read/write AVs or SIGABRT/SIGSEGV along with the file hashes. All unique crashes are triaged as it fuzzes and this data along with target output (as available) is also captured and placed as artifacts in the same directory. It's also possible to replay crashes with `--replay` and providing the crashing file. In `local` client mode, the input directory should contain a server greeting, response or otherwise data that a client would expect when connecting to a server. As of now only one "shot" is implementated for network fuzzing with no complex session support. The client is launched via command line and debugged the same as when file fuzzing. A listener is setup to support this scenario, yes its a slow and borderline manual labor but it works. If a crash is detected, it is replayed in gdb to get the triage details. In `remote` client mode, this works the same expect for no local debugging / crash triage. In *local* server mode, it's similar to local client mode and for `remote` server mode it just connects to a specified target and send mutated sample client data that the user specifies as inputs, but only a simple "can we still connect, if not then it probably crashed on the last one" triage is provided.

There are a few mutation functions written from scratch which mostly do random mutations with a random selection of inputs specified by the `-i` flag. For file fuzzing, just select local mode and pass it the target command line with FUZZ denoting where the app expects the filename to parse, eg. `tcpdump -r FUZZ` along with an input directory of "good files" to mutate. For network client fuzzing, it's similar to local fuzzing, but also provide connection specifics via `-a`. And if you want to fuzz servers, do server mode and provide a `protocol://address:port` just like for clients.

It fuzzes as fast as the target can consume the data and exit, such as the case for most CLI applications or for as long as you've determined it needs before the local execution or network connection times out, which can be much slower. No fancy exec or kernel tricks here. But of course if you write a harness that parses input and exits quickly, covering a specific part of the target, that helps too. But at that point, if you can get that close to the target, you're probably better off using [persistant mode](https://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html) or similar features that other fuzzers can offer.

In short...

### what it does
- runs on linux, windows and mac and supports py2/py3
- fuzzes CLI/GUI binaries that read from files/stdin
- fuzzes network clients and servers, open source or proprietary, available to debug locally or remote
- diffs, minimization, replay, sorting and auto-triaging of crashes
- misc stuff like TLS support, golang binary fuzzing and some extras for Mac
- mutates input with various built-in mutators + pyradamsa (Linux)

### what it doesn't do
- native instrumentation
- scale with concurrent jobs
- complex session fuzzing
- remote client and server monitoring (only basic checks eg. connect)

## support

Primarily tested on **Ubuntu Linux 20.04**, **Windows 10** and **Mac OS 11**. The fuzzer and setup scripts may work on slightly older or newer versions of these operating systems as well, but the majority of research, testing and development occurred in these environments. Python3 is supported and an effort was made to make the code compatiable with Python2 as well as it's necessary for fuzzing on Windows via [WinAppDbg](https://github.com/MarioVilas/winappdbg). Platform testing primarily occured on Intel-based hardware, but things seem to mostly work on Apple's M1 platform too (notable exceptions being on Linux the exploitable plugin for GDB probably isn't supported, nor is Pyradamsa). There are also setup scripts in setup/ to automate most or all of the tasks and depencency installation. It can generally fuzz native binaries on each platform, which are often compiled in C/C++, but it also catch crashes for Golang binaries as well (experimental).

### python versions

Python3 is supported for Linux and Mac while Python2 is required for Windows.

Why Py3 for Linux and Mac? Pyautogui, Pyradamsa (Linux only), better socket support on Mac.

Why Py2 for Windows? Winappdbg requires Py2.

### linux

GDB for debugging and [exploitable](https://github.com/jfoote/exploitable) for crash triage. If it's OSS, you can build and instrument the target with [sanitizers](https://fuzzing-project.org/tutorial2.html) and such, otherwise there's some [memory debuggers](https://en.wikibooks.org/wiki/Linux_Applications_Debugging_Techniques/Heap_corruption) we can just load at runtime.

This installation along with the python dependencies and other helpful stuff has been automated with [setup/linux.sh](setup/linux.sh). Recommended OS is Ubuntu 20.04 as that is where the majority of testing occurred.

### mac

Instead of gdb, we use lldb for debugging on OS X as it's included with the XCode command line tools. Being an admin or in the developer group should let you use lldb, but this behavior may differ across environments and versions and you may need to run it with sudo privileges if all else fails.

The one thing you'll manually need to do is turn off SIP (in recovery, via cmd+R or use vmware fusion hacks). Otherwise, auto-triage will fail when fuzzing on Tim Apple's OS.

Almost all of the setup has been automated with the [setup/mac.sh](setup/mac.sh) script, so you can just run it for a quick start.

### windows

[WinAppDbg](https://github.com/MarioVilas/winappdbg) is used for debugging on Windows with the slight caveat that stdin fuzzing isn't supported.

Like the automated setups for the other operating systems, chocolatey helps to automate package installation on windows. Run [setup/windows.bat](setup/windows.bat) in the litefuzz root directory as Administrator to automate the installations. It will install debugging tools and other dependencies to make things run smoothly.

### targets

This is a list of the types of targets that have been tested and are generally supported.

* Local CLI/GUI apps that parse file formats or stdin
  - debug support
 
* Local CLI/GUI network client that parses server responses
  - debug support for CLIs
  - limited debug support for GUIs
 
* Local CLI network server that parses client requests
  - debug support (caveat: must able to run as a standalone executable, otherwise can be treated as *remote*)

* Local GUI network server that parses client requests
  - theoretically supported, untested

* Remote CLI/GUI network client that parses server responses
  - no debug support

* Remote CLI/GUI network server that parses client requests
  - no debug support
  - exception being on Mac and using `attach` or `reportcrash` features

Again, the fuzzer can run on and support local apps, clients and servers on Linux, Mac and Windows and of course can fuzz remote stuff independent of the target platform.

### triage

* Local CLI/GUI apps that parse file formats or stdin
  - run app, catch signals, repro by running it again inside a debugger with the crasher
 
* Local CLI/GUI network client that parses server responses
  - run app, catch signals, repro by running it again inside a debugger with the crasher

* Local GUI/CLI network server that parses client requests
  - run app in debugger, catch signals, repro by running it again inside a debugger with the crasher

* Remote CLI/GUI network client that parses server responses
  - no visiblity, collect crashes from the remote side
  - can manually write supporting scripts to aid in triage

* Remote CLI/GUI network server that parses client requests
  - no visiblity, collect crashes from the remote side
  - can manually write supporting scripts to aid in triage
  - exception on Mac are the `attach` and `reportcrash` options, which can be used to enable some triage capabilities

## getting started

Most of the setup across platforms has been automated with the scripts in the [setup](https://github.com/sec-tools/litefuzz/blob/main/README.md#setup) directory. Simply run those from the litefuzz root and it should save you a lot of time and help enable some of what's needed for automated deployments. It's useful to use a VM to setup a clean OS and fuzzing environment as among other things its snapshot capabilities come in handy.

See [INSTALL.md](https://github.com/sec-tools/litefuzz/blob/main/INSTALL.md) for details.

### tests

#### unit tests
There are a few simple unit and functional tests to get some coverage for Litefuzz, but it is not meant to be complete.

```
py2> pytest
py3> python3 -m pytest
```

This will run pytest for `test_litefuzz.py` in the main directory and provide PASS/FAIL results once the test run is finished.

#### crashing app tests
A few examples of buggy apps for testing crash and triage capabilities on the different platforms can be found in the `test` folder.

- (a) null pointer dereference
- (b) divide-by-zero
- (c) heap overflow
- (d-gui) format string bug in a GUI
- (e) buffer overflow in client
- (f) buffer overflow in server

They are automatically built during setup and you can run them on the command line, in a debugger or use them to test as fuzzing targets. If running on Windows command line, check `Event Viewer -> Windows Logs -> Application` to see crashes.

## options
There are a ton of different options and features to take advantage of various target scenarios. The following is a brief explanation and some examples to help understand how to use them.

### crash directory
`-o` lets you specify a crash directory other than the default, which is the crashes/ in the local path. One can use this to manage crash folders for several concurrent fuzzing runs for different apps at the same time.

### insulate mode
`-u` insulates the target application from the normal fuzzing process, eg. execs or sending packets over and over and checking for crashes. Instead, this mode was made for interactive client applications, eg. Postman where you can script inside the application to repeat connections for client fuzzing. The target is ran inside of a debugger, the fuzzer is paused to get the user time to click a few buttons or sets the target's config to make it run automatically, user resumes and now you are fuzzing interactive network clients.

`litefuzz -lk -c "/snap/postman/140/usr/share/Postman/_Postman" -i input/http_responses -a tcp://localhost:8080 -u -n 100000 -z`

Insulate mode + refresh can be used for interactive clients, eg. run FileZilla in a debugger, but keep hitting F5 to make it reconnect to the server for each new iteration. Also, fuzzing local CLI/GUI servers are only started and ran once inside a debugger to make the process a little more efficient.

`--key` also allows you to send keys while fuzzing interactive targets, such as fuzzing FileZilla's parsing of FTP server responses by sending "refresh connection" with F5.

`litefuzz -lk -c "filezilla" -a tcp://localhost:2121 -i input/ftp/filezilla -u -pp --key "F5" -n 100 -z glibc`

note: insulate mode has only been tested working on Linux and is not supported on Windows.

### timeout
`-x secs` allows you to specify a timeout. In practice, this is more like "approx how long between iterations" for CLI targets and an actual timeout for GUIs.

### mutators
`--mutator N` specifies which mutator to use for fuzzing. If the option is not provided, a random choice from the list of available mutators is chosen for each fuzzing iteration. These mutators were written from scratch (with the exception of Radamsa of course). And while they have been extensively tested and have held up pretty well during millions of iterations, they may have subtle bugs from time to time, but generally this should not affect functionality.

```
FLIP_MUTATOR = 1
HIGHLOW_MUTATOR = 2
INSERT_MUTATOR = 3
REMOVE_MUTATOR = 4
CARVE_MUTATOR = 5
OVERWRITE_MUTATOR = 6
RADAMSA_MUTATOR = 7
```

note: [Radamsa](https://pypi.org/project/pyradamsa/) mutator is only available on Linux (+ Py3).

### ReportCrash
`--reportcrash` is mac-specific. Instead of using the default triage system, it instructs the fuzzer to monitor the ReportCrash directory for crash logs for the target process. ReportCrash must be enabled on OS X (default enabled, but usually disabled for normal fuzzing). This feature is useful in scenarios where we can't run the target in a debugger to generate and triage our own crash logs, but we can utilize this core functionality on the operating system to gain visibility.

note: consider this feature experimental as we're relying on a few moving parts and components we don't directly control within the core MacOS system. ReportCrash may eventually stop working properly and responding after fuzzing for a while even after attempting to unload and reload it, so one can try rebooting the machine or resetting the snapshot to get it back in good shape.

```
sudo launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
```

### pause
Hit ctrl+c to pause the fuzzing process. If you want to resume, choose `y` or `n` to stop. This feature works ok across platforms, but may be less reliable when fuzzing GUI apps.

### reusing crashes for variant finding

`-e` enables reuse mode. This means that if any crashes were found during the fuzzing run, they will be used as inputs for a second round of fuzzing which can help shake out even more bugs. Combine with `-z` for `-ez` bugs! Da-duph.

The following example is fuzzing antiword with 100000 iterations and then start another run with the same iteration count and options to reuse the crashes as input to try and grind out even more bugs.

`litefuzz -l -c "antiword FUZZ" -i docs -n 100000 -ez`

(or one could manually copy over crashes to an input directory to directly control the interations for the reuse run)

`litefuzz -l -c "antiword FUZZ" -i docs-crashes -n 500000 -z`

note: this mode is supported for local apps only.

### memory debugging helpers
`-z` enables Electric Fence (or glib malloc debugging as fallback) on Linux, Guard Malloc on Mac and PageHeap on Windows. Also, `-zz` can be used to disable PageHeap after enabling it for an application. If you want to just flip it on/off without starting the fuzzer, just leave out the `-i` flag. During Windows setup, [gsudo](https://github.com/gerardog/gsudo) is installed and can be used to run elevated commands on the command line, such as turning on PageHeap for targets.

`sudo litefuzz -l -c "notepad FUZZ" -i texts/files -z`

`sudo litefuzz -l -c "notepad FUZZ" -zz`

On Linux, specific helpers can be chosen. For example, instead of just using glib malloc as a fallback, it can be selected.

`litefuzz -l -c "geany FUZZ" -i texts/codes -z glibc`

The default Electric Fence malloc debugger is great, but it doesn't work with all targets. You can test the target with EF and if it crashes, select the glibc helper instead.

### checking live target output
If fuzzing local apps on Linux or Mac, you can `cat /tmp/litefuzz/RUN_ID/fuzz.out` to check what the latest stdout was from the target. `RUN_ID` is shown in the STATS information area when fuzzing begins. In the event that a crash occurs, stdout is also captured in the crashes directory as the `.out` file. Global stdout/stderr also goes to `/tmp/litefuzz/out` for debugging purposes as well for all fuzzing targets with the exception of insulated or local server modes which debugger output goes to `/tmp/litefuzz/RUN_ID/out`. Winappdbg doesn't natively support capturing stdout of targets (AFAIK), so this artifact is not available on Windows.

### client and server modes
If the server can be ran locally simply by executing the binary (with or without some flags and configuration), you can pass it's command line with `-c` and it will be started, fuzzed and killed with a new execution every iteration. The idea here is trading speed for the ability avoid those annoying bugs which triggered only after the target's memory is in a "certain state", which can lead to false positives. Same deal with locally fuzzing network clients. It even supports TLS connections, generating certificates for you on the fly (allowing the user to provide a client cert when fuzzing a server that requires it and certificate fuzzing itself are other ideas here). Debugging support is not provided by Litefuzz when fuzzing remote clients and servers, so setup on that remote end is up to the user. For servers, we simply check if the server stopped responding and note the previous payload as the crasher. This works fine for TCP connections, but we don't quite have this luxury for UDP services, so monitoring the remote server is left up to either the ReportCrash feature (available on Mac), running the target in a debugger (via local server mode or manually) or crafting custom supporting scripts. Also, some servers may auto-restart or otherwise recover after crashing, but there may be signs of this in the logs or other artifacts on the filesystem which can parsed by supporting scripts written for a particular target.

### local network examples

`litefuzz -lk -c "wget http://localhost:8080" -a tcp://localhost:8080 -i input/http -z`

`litefuzz -lk -c "curl -k https://localhost:8080" -a tcp://localhost:8080 -i input/http -z`

`litefuzz -lk -c "curl -k https://localhost:8080" -a tcp://localhost:8080 -i input/http -o crashes/curl --tls -n 100000 -z`

(open Wireshark and capture the response from a 
d, right click Simple Network Management Protocol -> Export Packet Bytes -> resp.bin)

`litefuzz -lk -c "snmpwalk -v 2c -c public localhost:1616 1.3.6.1.2.1.1.1" -a udp://localhost:1616 -i input/snmp/resp.bin -n 1 -d -x 3`

`litefuzz -ls -c "./sc_serv shoutcast.conf" -a localhost:8000 -i input/shouts -z`

`litefuzz -ls -c "snmpd" -i input/snmp -a udp://localhost:161 -z`

**quick notes**
- UDP sockets can act a little strange on Mac + Py2, so only Mac + Py3 has been tested and supported
- Local network client fuzzing on Windows can be buggy and should be considered experimental at this time

### remote network examples

Fuzzing remote clients and servers is a bit more challenging: we have no local debugging and rely on catching a halt in interaction between the two parties over the network to catch crashes. Also, since we are assumedly blind to what's happening on the other end, fuzzing ends when the client or server stops responding and needs to be restarted manually after the client or server is restored to a normal (uncrashed) state unless the user has setup scripts on the remote side to manage this process. Again, UDP complicates this further. Even sending a test packet to see if there's a listening service on a UDP port doesn't guarantee a reply. So it's possible to remotely fuzz network clients and servers, but there's a trade-off on visibility.

#### client

`while :; do echo "user test\rpass test\rls\rbye\r" | ftp localhost 2121; sleep 1; done`

`litefuzz -k -i input/ftp/test -a tcp://localhost:2121 -pp -n 100`

Client mode is more finicky here because it's hard to tell whether a client has actually crashed so it's not reconnecting or if the send/recv dance is just off as different clients can handle connections however they like. Also note that this just an example and that remote client fuzzing by nature is tricky and should be considered somewhat experimental.

#### server

The pros and cons of fuzzing a server locally or remotely can help you make a decision of how to approach a target when both options are available. Basically, fuzzing with the server in a debugger is going to be slower but you'll be able to get crash logs with the automatic triage, whereas fuzzing the server in remote mode (even pointing it to the localhost) will be much faster on average, but you lose the high visibility, debugger-based triage capabilities but it will give you time to manually restart the server after each crash to keep going before it exits (TCP servers only, feature does not support UDP-based servers).

**Shoutcast**

`./sc_serv ...`

`litefuzz -s -a localhost:8000 -i input/shouts -n 10000`

**SSHesame**

`sshesame`

`litefuzz -s -a tcp://target:2022 -i input/ssh-server -p -n 1000000 -x 0.05`

**FTP**

`litefuzz -s -a tcp://target:21 -i input/ftp/req.txt -pp -n 1000`

**DNS**

`coredns -dns.port 10000`

`litefuzz -ls -c "coredns -dns.port 10000" -a udp://localhost:10000 -i dns-req/1.bin -o crashes/coredns -n 10000`

or

`litefuzz -s -a udp://localhost:10000 -i dns-req/1.bin -o crashes/coredns -n 10000`

##### TLS

`litefuzz -s -a tcp://hostname:8080 -i input/http --tls -n 10000`

```
...
@ 48/10000 (1 crashes, 0 duplicates, ~7:13:18 remaining)

[!] check target, sleeping for 60 seconds before attempting to continue fuzzing...
```

note: default remote server mode delays between fuzzing iterations can make fuzzing sessions run reliably, but are pretty slow; this is the safe default, but one can use `-x` to set very fast timeouts between sessions (as shown above) if the target is OK parsing packets very quickly, unoffically nicknamed "2fast2furious" mode

For more on session-based protocols (such as FTP or SSH), see *Multiple* modes.

#### multiple data exchange modes

`-p` is for multiple binary data mode, which allows one to supply sequential inputs, eg. input/ssh directory containing files named "1", "2", "3", etc for each packet in the session to fuzz. This is meant to enable fuzzing of binary-based protocol implementations, such as SSH client.

`ls input/ssh`
`1  2  3  4`

`xxd input/ssh/2 | head`
```
00000000: 0000 041c 0a14 56ff 1297 dcf4 672d d5c9  ......V.....g-..
00000010: d0ab a781 dfcb 0000 00e6 6375 7276 6532  ..........curve2
00000020: 3535 3139 2d73 6861 3235 362c 6375 7276  5519-sha256,curv
00000030: 6532 3535 3139 2d73 6861 3235 3640 6c69  e25519-sha256@li
00000040: 6273 7368 2e6f 7267 2c65 6364 682d 7368  bssh.org,ecdh-sh
00000050: 6132 2d6e 6973 7470 3235 362c 6563 6468  a2-nistp256,ecdh
00000060: 2d73 6861 322d 6e69 7374 7033 3834 2c65  -sha2-nistp384,e
00000070: 6364 682d 7368 6132 2d6e 6973 7470 3532  cdh-sha2-nistp52
00000080: 312c 6469 6666 6965 2d68 656c 6c6d 616e  1,diffie-hellman
00000090: 2d67 726f 7570 2d65 7863 6861 6e67 652d  -group-exchange-
```

Each packet is consumed into an array, a random index is mutated and replayed to fuzz the target.

`litefuzz -lk -c "ssh -T test@localhost -p 2222" -a tcp://localhost:2222 -i input/ssh -o crashes/ssh -p -n 250000 -z glibc`

And you can check on the target's output for the latest iteration.

```
cat /tmp/litefuzz/out
kex_input_kexinit: discard proposal: string is too large
ssh_dispatch_run_fatal: Connection to 127.0.0.1 port 2222: string is too large

... and others like

ssh_dispatch_run_fatal: Connection to 127.0.0.1 port 2222: unknown or unsupported key type

ssh_askpass: exec(/usr/bin/ssh-askpass): No such file or directory
Host key verification failed.

Bad packet length 1869636974.
ssh_dispatch_run_fatal: Connection to 127.0.0.1 port 2222: message authentication code incorrect
```

`-pp` asks the fuzzer to check inputs for line breaks and if detected, treat those as multiple requests / responses. This is useful for simple network protocol fuzzing for mostly string-based protocol implementations, eg. ftp clients.

```
cat input/ftp/test
220 ProFTPD Server (Debian) [::ffff:localhost]
331 Password required for user
230 User user logged in
215 UNIX Type: L8
221 Goodbye
```

The fuzzer breaks each line into it's own FTP response to try and fuzz a client's handling of a session. There's no guarentee, however, that a client will "behave" or act in ways that don't allow a session to complete properly, so some trial and error + fine tuning for session test cases while running Wireshark can be helpful for understanding the differences in interaction between targets.

`litefuzz -lk -c "ftp localhost 2121" -a tcp://localhost:2121 -i input/ftp -o crashes/ftp -n 100000 -pp -z`

This can also be combined with *-u* for insulating GUI network targets like FileZilla.

`litefuzz -lk -c "filezilla" -a tcp://localhost:2121 -i input/ftp.resp -n 100000 -u -pp -z glibc`

### attaching to a process
If the target spawns a new process on connection, one can specify the name of a process (or pid) to attach to after a connection has been established to the server. This is handy in cases where eg. launchd is listening on a port and only launches the handling process once a client is connected. This is one feature that sort of blurs the line between local and remote fuzzing, as technically the fuzzer is in remote mode, yet we specify the target address as localhost and ask it to attach to a process.

`./litefuzz.py -s -a tcp://localhost:8080 -i input/shareserv -p --attach ShareServ -x 1 -n 100000`

note: currently this feature is only supported on Mac (LLDB) and for network fuzzing, although if implemented it should work fine for Linux (GDB) too.

### crash artifacts
When a crash is encountered during fuzzing, it is replayed in a debugger to produce debug artifacts and bucketing information. The information varies from platform to platform, but generally the a text file is produced with a backtrace, register information, `!exploitable` type stuff (where available) and other basic information.

**Memory dumps** can be enabled on Windows by passing the `--memdump` or disabled with `--nomemdump` similar to how malloc debuggers are controlled via `-z` and `-zz` respectively. If enabled, the dump will also be loaded in the console debugger (cdbg) and `!analyze -v` crash analysis output is captured within an additional memory dump crash analysis log. Winappdbg already has !exploitable type analysis that we get in the initial crash analysis, so we just do !analyze here.

`litefuzz -l -c "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" --memdump`

or to disable memory dumps for an application

`litefuzz -l -c "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" --nomemdump`

In addition to auto-crash triage, binary/string diffs (as appropriate) and target stdout (platform / target dependent) is also produced and repro files of course.

For local fuzzing, artifacts generally include diffs, stdout (linux/mac only), repro file and the crash log and information file.

```
$ ls crashes/latex
PROBABLY_EXPLOITABLE_SIGSEGV_XXXX5556XXXX_YYYYa39f3fd719e170234435a1185ee9e596c54e79092c72ef241eb7a41cYYYY.diff
PROBABLY_EXPLOITABLE_SIGSEGV_XXXX5556XXXX_YYYYa39f3fd719e170234435a1185ee9e596c54e79092c72ef241eb7a41cYYYY.diffs
PROBABLY_EXPLOITABLE_SIGSEGV_XXXX5556XXXX_YYYYa39f3fd719e170234435a1185ee9e596c54e79092c72ef241eb7a41cYYYY.out
PROBABLY_EXPLOITABLE_SIGSEGV_XXXX5556XXXX_YYYYa39f3fd719e170234435a1185ee9e596c54e79092c72ef241eb7a41cYYYY.tex
PROBABLY_EXPLOITABLE_SIGSEGV_XXXX5556XXXX_YYYYa39f3fd719e170234435a1185ee9e596c54e79092c72ef241eb7a41cYYYY.txt
```

On Windows, if memory dumps are enabled, a dump file will be generated and additional triage information will be written to an additional crash analysis log.

```
C:\litefuzz\crashes> dir
app.exe.14299_YYYYa39f3fd719e170234435a1185ee9e596c54e79092c72ef241eb7a41cYYYY.dmp
app.exe.14299_YYYYa39f3fd719e170234435a1185ee9e596c54e79092c72ef241eb7a41cYYYY.log
....
```

For remote fuzzing, artifacts may vary depending on the options chosen, but often include diffs, repro file and/or repro file directory (if input is a session with multiple packets), previous fuzzing iteration repro (prevent losing a bug in case its actually the crasher as remote fuzzing has its challenges) and crash log or brief information file.

```
ls crashes/serverd
REMOTE_SERVER_testbox.1_NNNN_XXXX9c3f3660aaa76f70515f120298f581adfa9caa8dcaba0f25a2bc0b78YYYY
REMOTE_SERVER_testbox.1_NNNN_PREV_XXXX9c3f3660aaa76f70515f120298f581adfa9caa8dcaba0f25a2bc0b78YYYY
UNKNOWN_XXXX2040YYYY_XXXX9c3f3660aaa76f70515f120298f581adfa9caa8dcaba0f25a2bc0b78YYYY.diff
UNKNOWN_XXXX2040YYYY_XXXX9c3f3660aaa76f70515f120298f581adfa9caa8dcaba0f25a2bc0b78YYYY.diffs
UNKNOWN_XXXX2040YYYY_XXXX9c3f3660aaa76f70515f120298f581adfa9caa8dcaba0f25a2bc0b78YYYY.txt
UNKNOWN_XXXX2040YYYY_XXXX9c3f3660aaa76f70515f120298f581adfa9caa8dcaba0f25a2bc0b78YYYY.zz

ls crashes/serverd/REMOTE_SERVER_localhost_NNNN_XXXX9c3f3660aaa76f70515f120298f581adfa9caa8dcaba0f25a2bc0b78YYYY
REMOTE_SERVER_testbox.1_NNNN_1.zz	REMOTE_SERVER_localhost_NNNN_2.zz
REMOTE_SERVER_testbox.1_NNNN_3.zz	REMOTE_SERVER_localhost_NNNN_4.zz
```

### golang
Apparently when Golang binaries crash, they may not actually go down with a traditional SIGSEGV, even if that's what they say in the panic info (Linux tested). They may instead crash with return code 2. So I guess that's what we're going with :) I'm sure there's a better explanation out there for how this works and edge cases around it, but one can use `--golang` to try and catch crashes in golang binaries on Linux.

`litefuzz -l -c "evernote2md FUZZ" -i input/enex -o crashes/evernote2md --golang -n 100000`

### repros
Crashing files are kept in the crashes/ directory (or otherwise specified by *-o* flag) along with diffs and crash info.

`-r` and passing a repro file (or directory) with the appropriate target command line / address setup will try and reproduce the crash locally or remote.

**local example**

`litefuzz -l -c "latex2rtf FUZZ" -r crashes/latex2rtf/test.tex -z`

**local network example**

`./litefuzz -ls -c "./sc_serv shoutcast.conf" -a tcp://localhost:8000 -r crashes/crash.raw`

**remote network example**

`litefuzz -s -a tcp://host:8000 -r crashes/crash.raw`

**remote network example (multiple packets)**

`litefuzz -s -a tcp://localhost:22 -r repro/dir/here`

### remove file
Some targets ask for a static outfile location as part of their command line and may throw an error if that file already exists. *--rmfile* is an option for getting around this while fuzzing where after each fuzzing iteration, it will remove the file that was generated as a part of how the target functions.

`litefuzz -l -c "hdiutil makehybrid -o /tmp/test.iso -joliet -iso FUZZ" -i input/dmg --rmfile /tmp/test.iso -n 500000 -ez`

### minimization
Minimizing crashing files is an interesting activity. You can even infer how a target is parsing data by comparing a repro with a minimized version.

`-m` and passing a repro file with the target command line or address setup will attempt to generate a minimized version of the repro which still crashes the target, but smaller and without bytes that may not be necessary. During this minimization journey, it may even find new crashes. Only local modes are supported, but this still includes local client and server modes, so you can minimize network crashes as long as we can debug them locally.

For example, this request is the original repro file.

```
GET /admin.cgi?pass=changeme&mode=debug&option=donotcrash HTTP/1.1
Host: localhost:8000
Connection: keep-alive
Authorization: Basic YWRtaW46Y2hhbmdlbWU=
Referer: http://localhost:8000/admin.cgi?mode=debug
```

Now take a look at it's minimized version.

```
GET /admin.cgi?mode=debug&option=a
Authorization:s YWRtaW46Y2hhbmdlbWU
Referer:admin.cgi
```

One can make some guesses about what the target is looking for and even the root cause of the crash.

1) The request is most important part
2) option= can probably be a lot of different things
3) The Host and Connection headers aren't neccesary
4) Authorization header parsing is just looking for the second token and doesn't care if it's explicitly presenting Basic auth
5) Referer is necessary, but only admin.cgi and not the host or URL

Anything else? Here's a bonus: passing a valid password isn't needed if the Authorization creds are correct, and visa-versa. Since the minimization is linear and starts at the beginning of the file and goes until it hits the end, we'd only produce a repro which authenticates this way, while still discovering there are actually two options!

`-mm` enables supermin mode. This is slower, but it will try and minimize over and over again until there's no more unnecessary bytes to remove.

For fun, we can modify the repro and run it through `supermin` to get the maximally minimized version.

```
GET /admin.cgi?pass=changeme&mode=debug&option=a
Referer:admin.cgi
```

**minimization examples**

`litefuzz -l -c "latex2rtf FUZZ" -m test.tex -z`

`litefuzz -ls -c "./sc_serv shoutcast.conf" -a "tcp://localhost:8000" -m repro.http`

**supermin example**

```
litefuzz -l -c "latex2rtf FUZZ" -mm crashes/latex2rtf/test.tex -z
...
[+] starting minimization

@ 582/582 (1 new crashes, 1145 -> 582 bytes, ~0:00:00 remaining)  

[+] reduced crash @ pc=55555556c141 -> pc=55555557c57d to 582 bytes

[+] supermin activated, continuing...

@ 299/299 (1 new crashes, 582 -> 300 bytes, ~0:00:00 remaining)

[+] reduced crash @ pc=55555557c57d to 300 bytes
...
[+] reduced crash @ pc=555555562170 to 17 bytes

@ 17/17 (2 new crashes, 17 -> 17 bytes, ~0:00:00 remaining)

[+] achieved maximum minimization @ 17 bytes (test.min.tex)

[RESULTS]
completed (17) iterations with 2 new crashes found
```

### command
`--cmd` allows a user to specify a command to run after each iteration. This can be used to cleanup certain operations that would otherwise take up resources on the system.

`litefuzz -l -c "/System/Library/CoreServices/DiskImageMounter.app/Contents/MacOS/DiskImageMounter FUZZ" -i input/dmg --cmd "umount /Volumes/test.dir" --click -x 5 -n 100000 -ez`

## examples

### local app

#### quick look
```
litefuzz -l -c "latex2rtf FUZZ" -i input/tex -o crashes/latex2rtf -x 1 -n 100
--========================--
--======| litefuzz |======--
--========================--

[STATS]
run id:     3516
cmdline:    latex2rtf FUZZ
crash dir:  crashes/latex2rtf
input dir:  input/tex
inputs:     4
iterations: 100
mutator:    random(mutators)

@ 100/100 (1 crashes, 4 duplicates, ~0:00:00 remaining)

[RESULTS]
> completed (100) iterations with (1) unique crashes and 4 dups
>> check crashes/latex2rtf dir for more details
```

#### enumerating file handlers on Ubuntu

```
$ cat /usr/share/applications/defaults.list
[Default Applications]
application/csv=libreoffice-calc.desktop
application/excel=libreoffice-calc.desktop
application/msexcel=libreoffice-calc.desktop
application/msword=libreoffice-writer.desktop
application/ogg=rhythmbox.desktop
application/oxps=org.gnome.Evince.desktop
application/postscript=org.gnome.Evince.desktop
....
```

**fuzz the local tcpdump's pcap parsing** (Linux)

`litefuzz -l -c "tcpdump -r FUZZ" -i test-pcaps`

**fuzz Evice document reader** (Linux GUI)

`litefuzz -l -c "evince FUZZ" -i input/oxps -x 1 -n 10000`

**fuzz antiword (oldie but good test app :)** (Linux)

`litefuzz -l -c "antiword FUZZ" -i input/doc -ez`

note: you can (and probably should) pass `-z` to enable [Electric Fence](https://linux.die.net/man/3/libefence) (or fallback to glibc's feature) for [heap error checking](https://blog.securityevaluators.com/electric-fence-who-let-the-heap-corruption-out-f40454737e20)

#### enumerating file handlers on OS X

[swda](https://github.com/Lord-Kamina/SwiftDefaultApps) can enumerate file handlers on Mac.

```
$ ./swda getUTIs | grep -Ev "No application set"
com.adobe.encapsulated-postscript       /System/Applications/Preview.app
com.adobe.flash.video             /System/Applications/QuickTime Player.app
com.adobe.pdf               /System/Applications/Preview.app
com.adobe.photoshop-image           /System/Applications/Preview.app
....
```

**fuzz gpg decryption via stdin with heap error checking** (Mac)

`litefuzz -l -c "gpg --decrypt" -i test-gpg -o crashes-gpg -z`

**fuzz Books app** (Mac GUI)

`litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i test-epub -t "/Users/test/Library/Containers/com.apple.iBooksX/Data" -x 8 -n 100000 -z`

note: `-z` here enables [Guard Malloc](https://www.manpagez.com/man/3/libgmalloc/) heap error checking in order to detect subtle heap corruption bugs

**mac note**

Some GUI targets may fail to be killed after each iteration's timeout and become unresponsive. To mitigate this, you can run a script that looks like this in another terminal to just periodically kill them in batch to reduce manual effort and monitoring, else the fuzzing process may be affected.

```
#!/bin/bash
ps -Af | grep -ie "$1" | awk '{print $2}' | xargs kill -9
```

```
$ while :; do ./pkill.sh "Process Name /Users/test"; sleep 360; done
```

*/Users/test* (example for the first part of the path where temp files are being passed to the local GUI app, FUZZ becomes a path during execution) was chosen as you need a unique string to kill for processes, and if you only use the Process Name, it will kill the fuzzing process as it contains the Process Name too.

**enumerating file handlers on Windows**

Using the [AssocQueryString](https://github.com/sec-tools/WindowsFileHandlerEnumeration/) script with the *assoc* command can map file extensions to default applications.

```
C:\> .\AssocQueryString.ps1
...
.hlp :: C:\Windows\winhlp32.exe
.hta :: C:\Windows\SysWOW64\mshta.exe
.htm :: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
.html :: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
.icc :: C:\Windows\system32\colorcpl.exe
.icm :: C:\Windows\system32\colorcpl.exe
.imesx :: C:\Windows\system32\IME\SHARED\imesearch.exe
.img :: C:\Windows\Explorer.exe
.inf :: C:\Windows\system32\NOTEPAD.EXE
.ini :: C:\Windows\system32\NOTEPAD.EXE
.iso :: C:\Windows\Explorer.exe
```

When fuzzing on Windows, you may want to enable PageHeap and Memory Dumps for a better fuzzing experience (unless your target doesn't like them) prior to starting a new fuzzing run.

`sudo litefuzz -l -c "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" -z`

`sudo litefuzz -l -c "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" --memdump`

Yes, run these commands using (g)sudo on Windows to easily elevate to Admin from the console and make the registry changes needed for the features to be enabled. And this also illustrates another nuance for enabling malloc debuggers for targets: on Linux and Mac, we're using runtime environment flags which need to be passed every time to enable this feature. For Windows, we're modifying the registry so once it's passed the first time, one doesn't need to pass `-z` or `--memdump` in the fuzzing command line again (unless to disable or re-enable them). 

**fuzz PuTTY (puttygen)** (Windows)

`litefuzz -l -c "C:\Program Files (x86)\WinSCP\PuTTY\puttygen.exe FUZZ" -i input\ppk -x 0.5 -n 100000 -z`

**fuzz Adobe Reader like back in the day** (Windows GUI)

`litefuzz -l -c "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe FUZZ" -i pdfs -x 3 -n 100000 -z`

(WinAppDbg only supports python 2, so must use py2 on Windows)

note: reminder that you can enable [PageHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-and-pageheap) for the target app via `-z` in an elevanted prompt or using the installed `sudo` for [gsudo](https://github.com/gerardog/gsudo) win32 package that was installed during setup

`litefuzz -l -c "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe FUZZ" -z`

### client

#### quick look
```
litefuzz -lk -c "ssh -T test@localhost -p 2222" -a tcp://localhost:2222 -i input/ssh-cli -o crashes/ssh -p -n 250000 -z glibc
--========================--
--======| litefuzz |======--
--========================--

[STATS]
run id:     9404
cmdline:    ssh -T test@localhost -p 2222
address:    tcp://localhost:2222
crash dir:  crashes/ssh
input dir:  input/ssh-cli
inputs:     4
iterations: 250000
mutator:    random(mutators)

@ 73/250000 (0 crashes, 0 duplicates, ~1 day, 0:21:01 remaining)^C

resume? (y/n)> n
Terminated
...

cat /tmp/litefuzz/out
padding error: need 57895 block 8 mod 7
ssh_dispatch_run_fatal: Connection to 127.0.0.1 port 2222: message authentication code incorrect
```

#### local client

**fuzz SNMP client on the localhost (Linux)**

`litefuzz -lk -c "snmpwalk -v 2c -c public localhost:1616 1.3.6.1.2.1.1.1" -a udp://localhost:1616 -i input/snmp/resp.bin -n 1 -d -x 3`

#### remote client

**fuzz a remote FTP client (Linux)**

`while :; do echo "user test\rpass test\rls\rbye\r" | ftp localhost 2121; sleep 1; done`

`litefuzz -k -i input/ftp/test -a tcp://localhost:2121 -n 100`

note: depending on the target, client fuzzing may require listening on a privileged port (1-1024). In this case, on Linux you can either `setcap cap_net_bind_service=+ep` on the python interpreter or use sudo when running the fuzzer, on Mac just use sudo and on Windows you can run the fuzzer as Administrator to avoid any Permission Denied errors.

### server

#### quick look
```
litefuzz -ls -c "./sc_serv shoutcast.conf" -a tcp://localhost:8000 -i input/shoutcast -o crashes/shoutcast -n 1000 -z
--========================--
--======| litefuzz |======--
--========================--

[STATS]
run id:     4001
cmdline:    ./sc_serv shoutcast.conf
address:    tcp://localhost:8000
crash dir:  crashes/shoutcast
input dir:  input/shoutcast
inputs:     3
iterations: 1000
mutator:    random(mutators)

@ 1000/1000 (1 crashes, 7 duplicates, ~0:00:00 remaining)

[RESULTS]
> completed (1000) iterations with (1) unique crashes and 7 dups
>> check crashes/shoutcast for more details
```

#### local server

**fuzz a local Shoutcast server**

`litefuzz -ls -c "./sc_serv shoutcast.conf" -a tcp://localhost:8000 -i input/shoutcast -o crashes/shoutcast -n 1000 -z`

#### remote server

**fuzz a remote SMTP server**

`litefuzz -s -a tcp://10.0.0.11:25 -i input/smtp-req -pp -n 10000`

# command line

```
usage: litefuzz.py [-h] [-l] [-k] [-s] [-c CMDLINE] [-i INPUTS] [-n ITERATIONS] [-x MAXTIME] [--mutator MUTATOR] [-a ADDRESS] [-o CRASHDIR] [-t TEMPDIR] [-f FUZZFILE]
                   [-m MINFILE] [-mm SUPERMIN] [-r REPROFILE] [-e] [-p] [-pp] [-u] [--nofuzz] [--key KEY] [--click] [--tls] [--golang] [--attach ATTACH] [--cmd CMD]
                   [--rmfile RMFILE] [--reportcrash REPORTCRASH] [--memdump] [--nomemdump] [-z [MALLOC]] [-zz] [-d]

optional arguments:
  -h, --help            show this help message and exit
  -l, --local           target will be executed locally
  -k, --client          target a network client
  -s, --server          target a network server
  -c CMDLINE, --cmdline CMDLINE
                        target command line
  -i INPUTS, --inputs INPUTS
                        input directory or file
  -n ITERATIONS, --iterations ITERATIONS
                        number of fuzzing iterations (default: 1)
  -x MAXTIME, --maxtime MAXTIME
                        timeout for the run (default: 1)
  --mutator MUTATOR, --mutator MUTATOR
                        timeout for the run (default: 0=random)
  -a ADDRESS, --address ADDRESS
                        server address in the ip:port format
  -o CRASHDIR, --crashdir CRASHDIR
                        specify the directory to output crashes (default: crashes)
  -t TEMPDIR, --tempdir TEMPDIR
                        specify the directory to output runtime fuzzing artifacts (default: OS tmp + run dir)
  -f FUZZFILE, --fuzzfile FUZZFILE
                        specify the path and filename to place the fuzzed file (default: OS tmp + run dir + fuzz_random.ext)
  -m MINFILE, --minfile MINFILE
                        specify a crashing file to generate a minimized version of it (bonus: may also find variant bugs)
  -mm SUPERMIN, --supermin SUPERMIN
                        loops minimize to grind on until no more bytes can be removed
  -r REPROFILE, --reprofile REPROFILE
                        specify a crashing file or directory to replay on the target
  -e, --reuse           enable second round fuzzing where any crashes found are reused as inputs
  -p, --multibin        use multiple requests or responses as inputs for fuzzing simple binary network sessions
  -pp, --multistr       use multiple requests or responses within input for fuzzing simple string-based network sessions
  -u, --insulate        only execute the target once and inside a debugger (eg. interactive clients)
  --nofuzz, --nofuzz    send input as-is without mutation (useful for debugging)
  --key KEY, --key KEY  send a particular key every iteration for interactive targets (eg. F5 for refresh)
  --click, --click      click the mouse (eg. position the cursor over target button to click beforehand)
  --tls, --tls          enable TLS for network fuzzing
  --golang, --golang    enable fuzzing of Golang binaries
  --attach ATTACH, --attach ATTACH
                        attach to a local server process name (mac only)
  --cmd CMD, --cmd CMD  execute this command after each fuzzing iteration (eg. umount /Volumes/test.dir)
  --rmfile RMFILE, --rmfile RMFILE
                        remove this file after every fuzzing iteration (eg. target won't overwrite output file)
  --reportcrash REPORTCRASH, --reportcrash REPORTCRASH
                        use ReportCrash to help catch crashes for a specified process name (mac only)
  --memdump, --memdump  enable memory dumps (win32)
  --nomemdump, --nomemdump
                        disable memory dumps (win32)
  -z [MALLOC], --malloc [MALLOC]
                        enable malloc debug helpers (free bugs, but perf cost)
  -zz, --nomalloc       disable malloc debug helpers (eg. pageheap)
  -d, --debug           Turn on debug statements
```

# trophies

Litefuzz has fuzzed crashes out of various software packages such as

* antiword
* AppleScript (OS X)
* ColorSync (OS X)
* Dynamsoft BarcodeReader
* eot2ttf
* evernote2md
* latex2rtf
* MiniWeb Server
* OSM Express
* PBRT-Parser
* RAE (OS X)
* Shoutcast Server
* syslog (OS X)
* TinyXML2
* Ulfius Web Framework
* zlib

# FAQ

## how did this project come about?
Fuzzing is fun! And it's nice to do projects which take a contrarian type of view that fuzzers don't always have to follow the modern or popular approaches to get to the end goal of finding bugs. Whether you're close to bare metal, getting code coverage across all paths or simply optimizing on the fast and flexible, the fundamental "invalidating assumptions" way of doing things, etc. However it manifests, enjoy it.

## is this project actively maintained?
Please do not expect active support or maintenance on the project. Feel free to fork it to add new features or fix bugs, etc. Perhaps even do a PR for smaller things, although please do no have no expectations for responses or troubleshooting. It is not intended for development on this repo to be active.

## how do you know the fuzzer is working well and did you measure it against others?
The purpose of Litefuzz is to find bugs across platforms. And it does. So, honestly the ability to measure it against fuzzerX or fuzzerY just didn't make the cut. Certain trade-offs were made and acknowledged at inception, see the [#intro](README.md#intro) for more details.

## what would you change if you were to re-write it today?
It works pretty well as it is and has been tested on a ton of different targets and scenarios. That being said, it could benefit standardizing on a more modular-based and plugin system where switching between targets and platforms didn't require as many additional checks in the operations side of the code, etc. Of course having more formal tests and a deployment system that would test it across supporting operating systems would create an environment that easier to work across when making changes to core functions. It grew from a small yet amibitious project into something a little bigger pretty quickly.

## how stable is litefuzz?
The command line, GUI, network fuzzing (mostly on Linux and Mac), minimization, etc has been tested pretty thoroughly and should be pretty solid overall. Some of the more exotic features such as insulated network GUI fuzzing, ReportCrash support for Mac and some other niche features should be considered experimental.

## are there unsupported scenarios for litefuzz?
A few of them, yes. But most are either uncommon scenarios that are buggy, required more time and research to "get right" or just don't quite work for platform related reasons. Many of them are explicitly exit with an "unsupported" message when you try to run it with such options and some caveats have been mentioned in the sections above when describing various features. Some of the more nuanced ones include repro mode on *insulated* apps isn't supported and also there's been limited testing on Mac apps using the insulate feature, Pyautogui seems to work fine on Linux and Windows but on Mac it didn't prove very reliable so consider it functionally unsupported and client fuzzing on Windows can be a little less reliable than other modes on other platforms.

There may be some edge cases here and there, but the most common local and network fuzzing scenarios have been tested and are working. Ah, these are joys of writing cross-platform tooling: rewarding, but it's hard to make everything work great all the time. Overall, fuzzing on Linux/Mac seems to be more stable and support more features overall, especially as it's had much more testing of network fuzzing than on the Windows platform, but an effort was made for at least the basics to be available on Win32 with a couple extras.

Feel free to fork this fuzzer and make such improvements, support the currently unsupported, etc or PRs for more minor but useful stuff.

## what guarentees are given for this project or it's code?
Absolutely none. But it's pretty fun to fuzz and watch it hand you bugs.

## author / references
- [Jeremy Brown](jbrown3264[NOSPAM]gmail)
- [Slide deck for macOS Fuzzing](https://www.slideshare.net/JeremyBrown37/summer-of-fuzz-macos)
