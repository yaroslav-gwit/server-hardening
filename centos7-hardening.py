#!/usr/bin/env python3
# native imports
import subprocess
import argparse
import re

# 3rd party imports
import jinja2
from colorama import Fore, Back, Style
from tabulate import tabulate

# Bold table headers
bolded_string_Task = "\033[1m" + "Task name" + "\033[0m"
bolded_string_Status = "\033[1m" + "Status" + "\033[0m"
bolded_string_Details = "\033[1m" + "Details" + "\033[0m"

# Table headers
table_headers = [bolded_string_Task, bolded_string_Status, bolded_string_Details]

# Coloured output
Failed = Fore.RED + 'Failed' + "\033[0m"
Passed = Fore.GREEN + 'Passed' + "\033[0m"
Fixed = Fore.YELLOW + 'Fixed' + "\033[0m"

# Table content
task_list = [
    ["Test passed task", Passed, "-"],
    ["Test failed task", Failed, "-"],
    ["Test fixed task", Fixed, "-"],
]


# Checks and fixes

### CRAMFS CHECK ###

#modprobe -n -v cramfs | grep -E '(cramfs|install)'
## Has to return "install /bin/true"
command = "sudo modprobe -n -v cramfs | grep -E '(cramfs|install)'"
run_command = subprocess.check_output(command, shell=True)
cramfs_file_check = run_command.decode("utf-8")

#lsmod | grep -c cramfs
## Has to return zero
command = "sudo lsmod | grep -c cramfs || true"
run_command = subprocess.check_output(command, shell=True)
cramfs_kmod_check = run_command.decode("utf-8")

if re.match("install /bin/true", cramfs_file_check) and re.match("0", cramfs_kmod_check):
    task_list.append(["CramFS", Passed, "-"])
else:
    task_list.append(["CramFS", Failed, "-"])

### CRAMFS FIX ###
#rmmod cramfs
## Run this is module is loaded
# Copy over cramfs.conf if it's not in place


### UDF File Systems ###
command = "sudo modprobe -n -v udf | grep -E '(udf|install)'"
run_command = subprocess.check_output(command, shell=True)
udf_file_check = run_command.decode("utf-8")

command = "sudo lsmod | grep -c udf || true"
run_command = subprocess.check_output(command, shell=True)
udf_kmod_check = run_command.decode("utf-8")

if re.match("install /bin/true", udf_file_check) and re.match("0", udf_kmod_check):
    task_list.append(["UDF File Systems", Passed, "-"])
else:
    task_list.append(["UDF File Systems", Failed, "-"])


# Table printout #
print(tabulate(task_list, table_headers, tablefmt="fancy_grid", showindex=range(1, len(task_list) + 1) ) )