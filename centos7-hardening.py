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
bloded_string_TotalScore = "\033[1m" + "Total System Hardening Points" + "\033[0m"

total_score = 0
lvl1_plus = 1
lvl2_plus = 1

# Table headers
table_headers = [bolded_string_Task, bolded_string_Status, bolded_string_Details]

# Coloured output
Failed = Fore.RED + 'Failed' + "\033[0m"
Passed = Fore.GREEN + 'Passed' + "\033[0m"
Fixed = Fore.YELLOW + 'Fixed' + "\033[0m"
RequiresManualFix = Fore.MAGENTA + 'Requires manual fix' + "\033[0m"

# Table content
task_list = [
    #["Test passed task", Passed, "-"],
    #["Test failed task", Failed, "-"],
    #["Test fixed task", Fixed, "-"],
]

# BASH scripts location:
bash_scripts_location = "/root/server-hardening/additional_bash_scripts/"

# Checks and fixes

check_name = "CramFS"
check_description = "-"
command = "sudo modprobe -n -v cramfs | grep -E '(cramfs|install)'"
run_command = subprocess.check_output(command, shell=True)
cramfs_file_check = run_command.decode("utf-8")

command = "sudo lsmod | grep -c cramfs || true"
run_command = subprocess.check_output(command, shell=True)
cramfs_kmod_check = run_command.decode("utf-8")

if re.match("install /bin/true", cramfs_file_check) and re.match("0", cramfs_kmod_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "UDF File Systems"
check_description = "-"
command = "sudo modprobe -n -v udf | grep -E '(udf|install)'"
run_command = subprocess.check_output(command, shell=True)
udf_file_check = run_command.decode("utf-8")

command = "sudo lsmod | grep -c udf || true"
run_command = subprocess.check_output(command, shell=True)
udf_kmod_check = run_command.decode("utf-8")

if re.match("install /bin/true", udf_file_check) and re.match("0", udf_kmod_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/TMP/ is configured as tmpfs"
check_description = "-"
command = "sudo findmnt -n /tmp"
run_command = subprocess.check_output(command, shell=True)
tmpfs_file_check_1 = run_command.decode("utf-8")

command = "sudo grep -E '\\s/tmp\\s' /etc/fstab | grep -E -v '^\\s*#'"
run_command = subprocess.check_output(command, shell=True)
tmpfs_file_check_2 = run_command.decode("utf-8")

if re.match("/tmp.*tmpfs.*tmpfs.*rw,nosuid,nodev,noexec,relatime,seclabel", tmpfs_file_check_1) and re.match("tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0", tmpfs_file_check_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/TMP/ noexec"
check_description = "-"
command = "sudo findmnt -n /tmp | grep -c -Ev '\\bnoexec\\b' || true"
run_command = subprocess.check_output(command, shell=True)
tmp_noexec_mount_check = run_command.decode("utf-8")

if re.match("0", tmp_noexec_mount_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/TMP/ nodev"
check_description = "-"
command = "sudo findmnt -n /tmp | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
tmp_nodev_mount_check = run_command.decode("utf-8")

if re.match("0", tmp_nodev_mount_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/TMP/ nosuid"
check_description = "-"
command = "sudo findmnt -n /tmp | grep -c -Ev '\\bnosuid\\b' || true"
run_command = subprocess.check_output(command, shell=True)
tmp_nosuid_mount_check = run_command.decode("utf-8")

if re.match("0", tmp_nosuid_mount_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/DEV/SHM/ is configured"
check_description = "-"
command = "sudo findmnt -n /dev/shm"
run_command = subprocess.check_output(command, shell=True)
devshm_mount_check_1 = run_command.decode("utf-8")

command = "sudo grep -E '\\s/dev/shm\\s' /etc/fstab"
run_command = subprocess.check_output(command, shell=True)
devshm_mount_check_2 = run_command.decode("utf-8")

if re.match("/dev/shm.*tmpfs.*tmpfs.*rw,nosuid,nodev,noexec,seclabel", devshm_mount_check_1) and re.match("tmpfs.*/dev/shm.*tmpfs.*defaults,noexec,nodev,nosuid,seclabel.*0.*0", devshm_mount_check_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/DEV/SHM/ noexec"
check_description = "-"
command = "sudo findmnt -n /dev/shm | grep -c -Ev '\\bnoexec\\b' || true"
run_command = subprocess.check_output(command, shell=True)
devshm_mount_noexec_check = run_command.decode("utf-8")

if re.match("0", devshm_mount_noexec_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/DEV/SHM/ nodev"
check_description = "-"
command = "sudo findmnt -n /dev/shm | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
devshm_mount_nodev_check = run_command.decode("utf-8")

if re.match("0", devshm_mount_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/DEV/SHM/ nosuid"
check_description = "-"
command = "sudo findmnt -n /dev/shm | grep -c -Ev '\\bnosuid\\b' || true"
run_command = subprocess.check_output(command, shell=True)
devshm_mount_nosuid_check = run_command.decode("utf-8")

if re.match("0", devshm_mount_nosuid_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


### LVL2 Check ###
check_name = "/VAR/ partition check"
check_description = "-"
command = "sudo findmnt /var | grep -c '/var' || true"
run_command = subprocess.check_output(command, shell=True)
var_partition_check = run_command.decode("utf-8")

if re.match("1", var_partition_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


### LVL2 Check ###
check_name = "/VAR/TMP/ partition check"
check_description = "-"
command = "sudo findmnt /var/tmp | wc -l"
run_command = subprocess.check_output(command, shell=True)
vartmp_partition_check = run_command.decode("utf-8")

if re.match("[^0]", vartmp_partition_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/VAR/TMP/ noexec"
check_description = "-"
command = "sudo findmnt -n /var/tmp | grep -c -Ev '\\bnoexec\\b' || true"
run_command = subprocess.check_output(command, shell=True)
vartmp_noexec_check = run_command.decode("utf-8")

if re.match("0", vartmp_noexec_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/VAR/TMP/ nodev"
check_description = "-"
command = "sudo findmnt -n /var/tmp | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
vartmp_nodev_check = run_command.decode("utf-8")

if re.match("0", vartmp_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/VAR/TMP/ nosuid"
check_description = "-"
command = "sudo findmnt -n /var/tmp | grep -c -Ev '\\bnosuid\\b' || true"
run_command = subprocess.check_output(command, shell=True)
vartmp_nosuid_check = run_command.decode("utf-8")

if re.match("0", vartmp_nosuid_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


### LVL2 Check ###
check_name = "/VAR/LOG/ partition check"
check_description = "-"
command = "sudo findmnt /var/log | wc -l"
run_command = subprocess.check_output(command, shell=True)
varlog_partition_check = run_command.decode("utf-8")

if re.match("[^0]", varlog_partition_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


### LVL2 Check ###
check_name = "/VAR/LOG/AUDIT/ partition check"
check_description = "-"
command = "sudo findmnt /var/log/audit | wc -l"
run_command = subprocess.check_output(command, shell=True)
varlogaudit_partition_check = run_command.decode("utf-8")

if re.match("[^0]", varlogaudit_partition_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


### LVL2 Check ###
check_name = "/HOME/ partition check"
check_description = "-"
command = "sudo findmnt /home | wc -l"
run_command = subprocess.check_output(command, shell=True)
home_partition_check = run_command.decode("utf-8")

if re.match("[^0]", home_partition_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "/HOME/ nodev"
check_description = "-"
command = "sudo findmnt -n /home | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
home_nodev_check = run_command.decode("utf-8")

if re.match("0", home_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Removable media noexec"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_removable_drives_noexec.sh | wc -l"
run_command = subprocess.check_output(command, shell=True)
rem_media_noexec_check = run_command.decode("utf-8")

if re.match("0", rem_media_noexec_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Removable media nodev"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_removable_drives_nodev.sh | wc -l"
run_command = subprocess.check_output(command, shell=True)
rem_media_nodev_check = run_command.decode("utf-8")

if re.match("0", rem_media_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Removable media nosuid"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_removable_drives_suid.sh | wc -l"
run_command = subprocess.check_output(command, shell=True)
rem_media_nosuid_check = run_command.decode("utf-8")

if re.match("0", rem_media_nosuid_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Sticky bit check"
check_description = "-"
command = "sudo df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | wc -l"
run_command = subprocess.check_output(command, shell=True)
sticky_bit_check = run_command.decode("utf-8")

if re.match("0", sticky_bit_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Disable automounting"
check_description = "-"
command = "sudo systemctl show \"autofs.service\" | grep -i unitfilestate=enabled | wc -l"
run_command = subprocess.check_output(command, shell=True)
disable_automounting = run_command.decode("utf-8")

if re.match("0", disable_automounting):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Disable USB Storage"
check_description = "-"
command = "sudo modprobe -n -v usb-storage"
run_command = subprocess.check_output(command, shell=True)
disable_usb_storage_file_check = run_command.decode("utf-8")

command = "sudo lsmod | grep usb-storage | wc -l"
run_command = subprocess.check_output(command, shell=True)
disable_usb_storage_kmod_check = run_command.decode("utf-8")

if re.match("install /bin/true", disable_usb_storage_file_check) and re.match("0", disable_usb_storage_kmod_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "GPG Check is globally activated"
check_description = "-"
command = "sudo grep \"^\\s*gpgcheck\" /etc/yum.conf"
run_command = subprocess.check_output(command, shell=True)
gpg_globally_activated_file_check = run_command.decode("utf-8")

command = "sudo grep -P '^\\h*gpgcheck=[^1\\n\\r]+\\b(\\h+.*)?$' /etc/yum.conf /etc/yum.repos.d/*.repo | wc -l"
run_command = subprocess.check_output(command, shell=True)
gpg_globally_activated = run_command.decode("utf-8")

if re.match("gpgcheck=1", gpg_globally_activated_file_check) and re.match("0", gpg_globally_activated):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "AIDE is installed"
check_description = "-"
command = "sudo rpm -q aide || true"
run_command = subprocess.check_output(command, shell=True)
aide_is_installed = run_command.decode("utf-8")

if re.match("package aide is not installed", aide_is_installed):
    task_list.append([check_name, Failed, check_description])
else:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus


check_name = "AIDE is scheduled to run periodically"
check_description = "-"
command = "sudo grep -c aide /etc/crontab || true"
run_command = subprocess.check_output(command, shell=True)
aide_is_scheduled = run_command.decode("utf-8")

if re.match("^[0]", aide_is_scheduled):
    task_list.append([check_name, Failed, check_description])
else:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus


check_name = "GRUB2 is password protected"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_bootloader_password.sh"
run_command = subprocess.check_output(command, shell=True)
grub2_is_password_protected = run_command.decode("utf-8")

if re.match("1", grub2_is_password_protected):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "GRUB2 config only accessible by root"
check_description = "-"
command = "sudo stat -c \"%a\" \"/boot/efi/EFI/centos/user.cfg\""
run_command = subprocess.check_output(command, shell=True)
grub2_config_root_access_only_user = run_command.decode("utf-8")

command = "sudo stat -c \"%a\" \"/boot/efi/EFI/centos/grub.cfg\""
run_command = subprocess.check_output(command, shell=True)
grub2_config_root_access_only_grub = run_command.decode("utf-8")

if re.match("700", grub2_config_root_access_only_user) and re.match("700", grub2_config_root_access_only_grub):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Authentication for single user mode"
check_description = "-"
command = "sudo grep /sbin/sulogin /usr/lib/systemd/system/rescue.service"
run_command = subprocess.check_output(command, shell=True)
auth_for_single_user_mode_1 = run_command.decode("utf-8")

command = "sudo grep /sbin/sulogin /usr/lib/systemd/system/emergency.service"
run_command = subprocess.check_output(command, shell=True)
auth_for_single_user_mode_2 = run_command.decode("utf-8")

if re.match("ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"", auth_for_single_user_mode_1) and re.match("ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"", auth_for_single_user_mode_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Resticted core dumps"
check_description = "-"

command = "sudo grep -E \"^\\s*\\*\\s+hard\\s+core\" /etc/security/limits.conf"
run_command = subprocess.check_output(command, shell=True)
restricted_core_dumps_1 = run_command.decode("utf-8")
restricted_core_dumps_1_regex = "\* hard core 0"

command = "sudo sysctl fs.suid_dumpable"
run_command = subprocess.check_output(command, shell=True)
restricted_core_dumps_2 = run_command.decode("utf-8")
restricted_core_dumps_2_regex = "fs.suid_dumpable = 0"

command = "sudo grep \"fs\\.suid_dumpable\" /etc/sysctl.conf"
run_command = subprocess.check_output(command, shell=True)
restricted_core_dumps_3 = run_command.decode("utf-8")
restricted_core_dumps_3_regex = "fs.suid_dumpable = 0"

command = "sudo systemctl is-enabled coredump.service 2> /dev/null | wc -l || true"
run_command = subprocess.check_output(command, shell=True)
restricted_core_dumps_4 = run_command.decode("utf-8")
restricted_core_dumps_4_regex = "0"

if re.match(restricted_core_dumps_1_regex, restricted_core_dumps_1) and re.match(restricted_core_dumps_2_regex, restricted_core_dumps_2) and re.match(restricted_core_dumps_3_regex, restricted_core_dumps_3) and re.match(restricted_core_dumps_4_regex, restricted_core_dumps_4):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "XD/NX support is enabled"
check_description = "-"
command = "sudo journalctl | grep 'protection: active'"
run_command = subprocess.check_output(command, shell=True)
xd_nx_support_enabled = run_command.decode("utf-8")

if re.match(".*protection: active.*", xd_nx_support_enabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Address space layout randomization (ASLR) is enabled"
check_description = "-"
aslr_is_enabled_regex = "kernel.randomize_va_space = 2"

command = "sudo sysctl kernel.randomize_va_space"
run_command = subprocess.check_output(command, shell=True)
aslr_is_enabled_1 = run_command.decode("utf-8")

command = "sudo grep \"kernel\\.randomize_va_space\" /etc/sysctl.conf"
run_command = subprocess.check_output(command, shell=True)
aslr_is_enabled_2 = run_command.decode("utf-8")

if re.match(aslr_is_enabled_regex, aslr_is_enabled_1) and re.match(aslr_is_enabled_regex, aslr_is_enabled_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "prelink is not installed"
check_description = "-"

command = "sudo rpm -q prelink || true"
run_command = subprocess.check_output(command, shell=True)
prelink_is_not_installed = run_command.decode("utf-8")

if re.match("package prelink is not installed", prelink_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "SELinux is installed"
check_description = "-"

command = "sudo rpm -q libselinux || true"
run_command = subprocess.check_output(command, shell=True)
selinux_is_installed = run_command.decode("utf-8")

if re.match("libselinux-.*", selinux_is_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "SELinux is not disabled during boot"
check_description = "-"

command = "sudo grep -Eq \"(selinux=0|enforcing=0)\" /boot/efi/EFI/centos/grub.cfg | wc -l || true"
run_command = subprocess.check_output(command, shell=True)
selinux_is_not_disabled_in_grubcfg = run_command.decode("utf-8")

if re.match("0", selinux_is_not_disabled_in_grubcfg):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "SELinux policy is configured"
check_description = "-"

command = "sudo grep -G \"^SELINUXTYPE=\" /etc/selinux/config || true"
run_command = subprocess.check_output(command, shell=True)
selinux_policy_is_configured = run_command.decode("utf-8")

if re.match("SELINUXTYPE=targeted", selinux_policy_is_configured):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "SELinux mode is enforcing or permissive"
check_description = "We are running SELinux in permissive mode only."

command = "sudo getenforce"
run_command = subprocess.check_output(command, shell=True)
selinux_mode_1 = run_command.decode("utf-8")

command = "sudo grep -Ei '^\\s*SELINUX=(enforcing|permissive)' /etc/selinux/config"
run_command = subprocess.check_output(command, shell=True)
selinux_mode_2 = run_command.decode("utf-8")

if re.match("Permissive", selinux_mode_1) and re.match("SELINUX=permissive", selinux_mode_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "No unconfined services exist"
check_description = "-"

command = "sudo ps -eZ | grep unconfined_service_t | wc -l"
run_command = subprocess.check_output(command, shell=True)
unconfigured_services_check = run_command.decode("utf-8")

if re.match("0", unconfigured_services_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "SETroubleshoot is not installed"
check_description = "-"

command = "sudo rpm -q setroubleshoot || true"
run_command = subprocess.check_output(command, shell=True)
setroubleshoot_is_not_installed = run_command.decode("utf-8")

if re.match("package setroubleshoot is not installed", setroubleshoot_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "mcstrans is not installed"
check_description = "-"

command = "sudo rpm -q mcstrans || true"
run_command = subprocess.check_output(command, shell=True)
mcstrans_is_not_installed = run_command.decode("utf-8")

if re.match("package mcstrans is not installed", mcstrans_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Message of the day is configured"
check_description = "-"
command = "sudo grep \"UNAUTHORISED ACCESS TO THIS DEVICE IS PROHIBITED\" /etc/motd | wc -l"
run_command = subprocess.check_output(command, shell=True)
motd_is_configued = run_command.decode("utf-8")

if re.match("1", motd_is_configued):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Local login warning banner is configured"
check_description = "-"
command = "sudo cat /etc/issue"
run_command = subprocess.check_output(command, shell=True)
etc_issue_is_configured = run_command.decode("utf-8")

if re.match("Authorized users only. All activity may be monitored and reported.", etc_issue_is_configured):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Remote login warning banner is configured"
check_description = "-"
command = "sudo cat /etc/issue.net"
run_command = subprocess.check_output(command, shell=True)
etc_issue_net_is_configured = run_command.decode("utf-8")

if re.match("Authorized users only. All activity may be monitored and reported.", etc_issue_net_is_configured):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Permissions on /etc/motd"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/motd\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_motd = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_motd):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Permissions on /etc/issue"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/issue\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_issue = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_issue):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Permissions on /etc/issue.net"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/issue.net\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_issue_net = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_issue_net):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "xinetd is not installed"
check_description = "-"

command = "sudo rpm -q xinetd_is_not_installed || true"
run_command = subprocess.check_output(command, shell=True)
xinetd_is_not_installed = run_command.decode("utf-8")

if re.match("package setroubleshoot is not installed", xinetd_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


# Table printout #
print(tabulate(task_list, table_headers, tablefmt="fancy_grid", showindex=range(1, len(task_list) + 1) ) )
print(bloded_string_TotalScore + ": " + str(total_score))
print()
print("To do:")
print(" - Configure and check automatic updates. Page 148.")
print()