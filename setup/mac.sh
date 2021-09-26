#!/usr/bin/env bash
#
# mac.sh
#
# litefuzz project
#
# setup and install deps on Mac OS X (10: TODO and 11 tested)
#
# note: run as user with sudo privileges and in the litefuzz root directory
#

echo -e '\ninstalling litefuzz deps and setup on Mac...'

#
# setup sudo user and groups
#
# note: nopasswd sudo is technically optional, but it allows us to sudo unattended for the rest of
# the setup and will probably come in handy later eg. if fuzzing clients that talk to privileged ports
#
echo -e '\n> configuring nopasswd sudo + dev groups for the current user, so enter your password if prompted\n'

echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" | (sudo EDITOR="tee -a" visudo)

sudo dseditgroup -o edit -a $(whoami) -t user admin
sudo dseditgroup -o edit -a $(whoami) -t user _developer

#
# install xcode and enable developer mode
#
# note: if xcode setup fails with NSURLErrorDomain error, check your network connection
#
echo -e '\n> installing xcode... hang tight as the download may take a while\n'

chmod +x setup/mac-xcode.sh
INSTALL_XCODE_CLI_TOOLS=true sudo -E setup/mac-xcode.sh

sudo DevToolsSecurity -enable

#
# python2 pip (py2 is recommended)
#
echo -e '\n> installing py2\n'

curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
python get-pip.py
rm get-pip.py

# export PATH=$PATH:/Users/$(whoami)/Library/Python/2.7/bin

echo -e '\n> installing python packages\n'

pip install -r requirements/requirements-py2.txt --user
pip3 install -r requirements/requirements-py3.txt --user

#
# disable ReportCrash
#
# note: enable it later if you intend on using the --reportcrash feature
#
echo -e '\n> disabling ReportCrash and friends\n'

launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#
# disable computer sleeping so it doesn't interfere with the fuzzing process
#
echo -e '\n> disabling system sleep modes'

# sudo pmset -a sleep 0
# sudo pmset -a disksleep 0
sudo systemsetup -setsleep Never

#
# try to avoid SSH timeouts
#
echo -e '\n> reconfiguring SSH'

# sudo echo -e 'TCPKeepAlive yes\nClientAliveInterval 0\nClientAliveMax 0' >> /etc/ssh/sshd_config
sudo bash -c "echo -e 'TCPKeepAlive yes\nClientAliveInterval 0\nClientAliveMax 0' >> sshd_config"
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist

#
# brew.sh
#
echo -e '\n> installing brew and packages\n'

/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" </dev/null
brew install gtk+3
brew install --cask keepingyouawake

#
# keepingyouawake auto-enabled config
#
defaults write info.marcel-dierkes.KeepingYouAwake info.marcel-dierkes.KeepingYouAwake.ActivateOnLaunch -bool YES

echo -e '\n> making test crash apps\n'

pushd test/mac
make
popd

chmod +x litefuzz.py

echo -e '\nfinished!\n'
echo -e 'note: if you see errors with the xcode install, try and run the xcode script directly'

#
# disable SIP so we can do auto-triage upon crashes
#
# (lldb) run ...
# error: process exited with status -1 (this is a non-interactive debug session, cannot get permission to debug processes.)
#
echo -e '\nok, just one last thing: you need to boot into recovery mode and disable SIP so that debugging actually works\n'
echo -e '1.1) For bare metal, reboot and hold down Command + R until you see the Apple logo or spinning thing'
echo -e '1.2) For virtual machines, search for instructions specific to OS X or OS 11, Temporary Installation Source Disk, Restart to Firmware, etc'
echo -e '2) At the top menu bar select Utilities -> Terminal'
echo -e '3) csrutil disable and then reboot\n'
