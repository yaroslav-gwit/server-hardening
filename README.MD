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
From root user, run this command:
```
git pull this-project-com
```

Initialize virtual environment:
```
cd this-project-com
python3 -m venv .
```

Activate the virtual environment:
```
activate bin/bash
```

Install PIP dependencies:
```
python3 -m pip install  --upgrade pip
python3 -m pip install -r requiremenets.txt
```

<br>
<br>

# Script removal
It's enough to remove the folder that was created by `git pull` command. From `root` user run this sequense of commands:
```
cd
rm -rf this-project-com
```

<br>
<br>

# Update to the latest verion
Run this from `root` user to update this script to the latest verion:
```
cd
cd this-project-com
git pull
```

That's it. You are running the latest version of a script.