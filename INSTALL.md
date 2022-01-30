In a command terminal, clone the repro and run the appropriate setup script for your OS.

```
git clone https://github.com/sec-tools/litefuzz
cd litefuzz
chmod +x setup/[OS].sh (linux/mac)
setup/[OS][.sh|bat]
```

### linux
Make sure you run it as a user that has sudo privileges.

`user@box:~$ setup/linux.sh`

note: if using py2, ignore any Pyradamsa pip failures as Pyradamsa supports py3 only.

### mac
Again, make sure you run it as a user that has sudo privileges.

`mac:~ user$ setup/mac.sh`

### windows
Open an Administrator command prompt and run the script. It will pull down a lot of packages, so it may take some time for the setup to complete.

`C:\litefuzz> setup\windows.bat`
