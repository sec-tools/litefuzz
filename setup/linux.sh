#!/usr/bin/env bash
#
# linux.sh
#
# litefuzz project
#
# setup and install deps on Ubuntu Linux (20.04 tested + Py3)
#
# note: run as user with sudo privileges and in the litefuzz root directory
#

echo "\ninstalling litefuzz deps and setup on Ubuntu Linux..."

echo -e '\n> installing apt packages, enter the password for sudo if prompted\n'

sudo apt update
sudo apt install -y build-essential gnome-devel gcc gdb libgtk-3-dev python3 python3-dev python3-pip python3-tk python-tk python-dev electric-fence

echo -e '\n> grabbing !exploitable for gdb\n'

git clone https://github.com/jfoote/exploitable
pushd exploitable
sudo python3 setup.py install
popd

#
# make exploitable autoload in gdb
#
EXPLOITABLE_PY=$(sudo find /usr/local/lib -name exploitable.py)
echo "source $EXPLOITABLE_PY" >> ~/.gdbinit

echo -e '\n> installing python packages and setting py3 as the default python\n'

pip3 install -r requirements/requirements-py3.txt
pip3 install pyradamsa # didn't include in requirements as its a Linux only package

sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1

echo -e '\n> making test crash apps\n'

pushd test/linux
make
popd

chmod +x litefuzz.py

echo -e '\nfinished!\n'
