# Script overview
This command will check if the system is up to date on hardening, and report any missing items:
```
centos7-hardening.py --check
```

This command will try and fix anything it can, will send you a report to the screen of items it fixed or didn't fix:
```
centos7-hardening.py --tryfix
```

Ideally you would run `--check` first, to see if it starts correctly and if there are any missing dependencies, etc. Then run `--tryfix`, which will do most of the powerlifting for you, and report back anything that needs to be done manually.

<br>
<br>

# Script installation
Install `python3` and `python3-pip`
```
yum install python3 python3-pip
```

From root user, run this command:
```
git clone https://github.com/yaroslav-gwit/server-hardening.git
```

Initialize virtual environment:
```
cd
cd server-hardening
python3 -m venv .
```

Activate the virtual environment:
```
source bin/activate
```

Install PIP dependencies:
```
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

<br>
<br>

# Script removal
It's enough to remove the folder that was created by `git clone` command. From `root` user run this sequense of commands:
```
cd
rm -rf server-hardening
```

<br>
<br>

# Update to the latest verion
Run this from `root` user to update this script to the latest verion:
```
cd
cd server-hardening
git pull
```

That's it. You are running the latest version of a script.