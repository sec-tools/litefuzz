#!/bin/sh
#
# mac-xcode.sh
#
# full credit and source: https://github.com/timsutton/osx-vm-templates/blob/master/scripts/xcode-cli-tools.sh
#
# catalina fix from: https://apple.stackexchange.com/questions/107307/how-can-i-install-the-command-line-tools-completely-from-the-command-line#comment553658_195963
#
# updated first check to support OS X 11+
#

if [[ ! "$INSTALL_XCODE_CLI_TOOLS" =~ ^(true|yes|on|1|TRUE|YES|ON])$ ]]; then
    exit
fi

# Get and install Xcode CLI tools
OSX_BIG_VERS=$(sw_vers -productVersion | awk -F "." '{print $1}')
OSX_VERS=$(sw_vers -productVersion | awk -F "." '{print $2}')

# on 10.9+, we can leverage SUS to get the latest CLI tools
if [ "$OSX_VERS" -ge 9 ] || [ "$OSX_BIG_VERS" -ge 11 ]; then
    # create the placeholder file that's checked by CLI updates' .dist code
    # in Apple's SUS catalog
    touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    # find the CLI Tools update
    #PROD=$(softwareupdate -l | grep "\*.*Command Line" | tail -n 1 | awk -F"*" '{print $2}' | sed -e 's/^ *//' | tr -d '\n')
    PROD=$(softwareupdate -l | grep "*.*Command Line" | tail -n 1 | awk -F"*" '{print $2}' | sed -e 's/^ *//' | sed 's/Label: //g' | tr -d '\n')
    # install it
    softwareupdate -i "$PROD" --verbose
    rm /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress

# on 10.7/10.8, we instead download from public download URLs, which can be found in
# the dvtdownloadableindex:
# https://devimages.apple.com.edgekey.net/downloads/xcode/simulators/index-3905972D-B609-49CE-8D06-51ADC78E07BC.dvtdownloadableindex
else
    [ "$OSX_VERS" -eq 7 ] && DMGURL=http://devimages.apple.com.edgekey.net/downloads/xcode/command_line_tools_for_xcode_os_x_lion_april_2013.dmg
    [ "$OSX_VERS" -eq 8 ] && DMGURL=http://devimages.apple.com.edgekey.net/downloads/xcode/command_line_tools_for_osx_mountain_lion_april_2014.dmg

    TOOLS=clitools.dmg
    curl "$DMGURL" -o "$TOOLS"
    TMPMOUNT=`/usr/bin/mktemp -d /tmp/clitools.XXXX`
    hdiutil attach "$TOOLS" -mountpoint "$TMPMOUNT"
    if [ "$OSX_VERS" -eq 7 ]; then
        # using '-allowUntrusted' because Lion CLI tools are so old Apple never built another
        # package that doesn't have an expired CA cert. (Expired February 15, 2015)
        installer -pkg "$(find $TMPMOUNT -name '*.mpkg')" -allowUntrusted -target /
    else
        installer -pkg "$(find $TMPMOUNT -name '*.mpkg')" -target /
    fi
    hdiutil detach "$TMPMOUNT"
    rm -rf "$TMPMOUNT"
    rm "$TOOLS"
    exit
fi