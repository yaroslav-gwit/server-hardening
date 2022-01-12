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
command = "sudo df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | wc -l"
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

command = "sudo systemctl is-enabled coredump.service 2>/dev/null | wc -l || true"
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


check_name = "644 permissions on /etc/motd"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/motd\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_motd = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_motd):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "644 permissions on /etc/issue"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/issue\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_issue = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_issue):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "644 permissions on /etc/issue.net"
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

command = "sudo rpm -q xinetd || true"
run_command = subprocess.check_output(command, shell=True)
xinetd_is_not_installed = run_command.decode("utf-8")

if re.match("package xinetd is not installed", xinetd_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Time sync is in use"
check_description = "This check shows if chrony is installed"

command = "sudo rpm -q chrony || true"
run_command = subprocess.check_output(command, shell=True)
chrony_is_installed = run_command.decode("utf-8")

if re.match("chrony-", chrony_is_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "chrony is configured"
check_description = "-"

command = "sudo grep -G \"^server\\|^pool\" /etc/chrony.conf | wc -l"
run_command = subprocess.check_output(command, shell=True)
chrony_is_configured_1 = run_command.decode("utf-8")

command = "systemctl is-enabled chronyd 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
chrony_is_configured_2 = run_command.decode("utf-8")

if re.match("[^0]", chrony_is_configured_1) and re.match("enabled", chrony_is_configured_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Avahi Server is not installed"
check_description = "-"

command = "sudo rpm -q avahi-autoipd || true"
run_command = subprocess.check_output(command, shell=True)
avahi_server_is_not_installed_1 = run_command.decode("utf-8")

command = "sudo rpm -q avahi || true"
run_command = subprocess.check_output(command, shell=True)
avahi_server_is_not_installed_2 = run_command.decode("utf-8")

if re.match("package avahi-autoipd is not installed", avahi_server_is_not_installed_1) and re.match("package avahi is not installed", avahi_server_is_not_installed_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "DHCP server is not installed"
check_description = "-"

command = "sudo rpm -q dhcp || true"
run_command = subprocess.check_output(command, shell=True)
dhcp_server_is_not_installed = run_command.decode("utf-8")

if re.match("package dhcp is not installed", dhcp_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "LDAP server is not installed"
check_description = "-"

command = "sudo rpm -q openldap-servers || true"
run_command = subprocess.check_output(command, shell=True)
ldap_server_is_not_installed = run_command.decode("utf-8")

if re.match("package openldap-servers is not installed", ldap_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "DNS server is not installed"
check_description = "-"

command = "sudo rpm -q bind || true"
run_command = subprocess.check_output(command, shell=True)
dns_server_is_not_installed = run_command.decode("utf-8")

if re.match("package bind is not installed", dns_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "FTP server is not installed"
check_description = "-"

command = "sudo rpm -q vsftpd || true"
run_command = subprocess.check_output(command, shell=True)
ftp_server_is_not_installed = run_command.decode("utf-8")

if re.match("package vsftpd is not installed", ftp_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "HTTP server (apache2) is not installed"
check_description = "-"

command = "sudo rpm -q httpd || true"
run_command = subprocess.check_output(command, shell=True)
httpd_server_is_not_installed = run_command.decode("utf-8")

if re.match("package httpd is not installed", httpd_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "IMAP and POP3 (dovecot) server is not installed"
check_description = "-"

command = "sudo rpm -q dovecot || true"
run_command = subprocess.check_output(command, shell=True)
dovecot_server_is_not_installed = run_command.decode("utf-8")

if re.match("package dovecot is not installed", dovecot_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "SAMBA is not installed"
check_description = "-"

command = "sudo rpm -q samba || true"
run_command = subprocess.check_output(command, shell=True)
samba_is_not_installed = run_command.decode("utf-8")

if re.match("package samba is not installed", samba_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "HTTP Proxy Server is not installed"
check_description = "-"

command = "sudo rpm -q squid || true"
run_command = subprocess.check_output(command, shell=True)
squid_is_not_installed = run_command.decode("utf-8")

if re.match("package squid is not installed", squid_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "net-snmp is not installed"
check_description = "-"

command = "sudo rpm -q net-snmp || true"
run_command = subprocess.check_output(command, shell=True)
net_snmp_is_not_installed = run_command.decode("utf-8")

if re.match("package net-snmp is not installed", net_snmp_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "NIS server is not installed"
check_description = "-"

command = "sudo rpm -q ypserv || true"
run_command = subprocess.check_output(command, shell=True)
ypserv_is_not_installed = run_command.decode("utf-8")

if re.match("package ypserv is not installed", ypserv_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "telnet-server is not installed"
check_description = "-"

command = "sudo rpm -q telnet-server || true"
run_command = subprocess.check_output(command, shell=True)
telnet_server_is_not_installed = run_command.decode("utf-8")

if re.match("package telnet-server is not installed", telnet_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "MTA is configured for local-only mode"
check_description = "-"

command = "sudo ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s' | wc -l"
run_command = subprocess.check_output(command, shell=True)
mta_local_only_mode = run_command.decode("utf-8")

if re.match("0", mta_local_only_mode):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "nfs-utils is not installed (or nfs server disabled)"
check_description = "-"

command = "sudo rpm -q nfs-utils || true"
run_command = subprocess.check_output(command, shell=True)
nfs_utils_is_not_installed = run_command.decode("utf-8")

command = "sudo systemctl is-enabled nfs-server 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
nfs_server_is_disabled = run_command.decode("utf-8")

if re.match("package nfs-utils is not installed", nfs_utils_is_not_installed) or re.match("masked|disabled", nfs_server_is_disabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "rpcbind is not installed (or rpcbind service is disabled)"
check_description = "-"

command = "sudo rpm -q rpcbind || true"
run_command = subprocess.check_output(command, shell=True)
rpcbind_is_not_installed = run_command.decode("utf-8")

command = "sudo systemctl is-enabled rpcbind 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rpcbind_is_disabled = run_command.decode("utf-8")

if re.match("package rpcbind is not installed", rpcbind_is_not_installed) or re.match("masked|disabled", rpcbind_is_disabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "rsync is not installed (or rsyncd service is disabled)"
check_description = "-"

command = "sudo rpm -q rsync || true"
run_command = subprocess.check_output(command, shell=True)
rsync_is_not_installed = run_command.decode("utf-8")

command = "sudo systemctl is-enabled rsyncd 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rsyncd_is_disabled = run_command.decode("utf-8")

if re.match("package rsync is not installed", rsync_is_not_installed) or re.match("masked|disabled", rsyncd_is_disabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "NIS client is not installed"
check_description = "-"

command = "sudo rpm -q ypbind || true"
run_command = subprocess.check_output(command, shell=True)
ypbind_is_not_installed = run_command.decode("utf-8")

if re.match("package ypbind is not installed", ypbind_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "rsh client is not installed"
check_description = "-"

command = "sudo rpm -q rsh || true"
run_command = subprocess.check_output(command, shell=True)
rsh_is_not_installed = run_command.decode("utf-8")

if re.match("package rsh is not installed", rsh_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "talk is not installed"
check_description = "-"

command = "sudo rpm -q talk || true"
run_command = subprocess.check_output(command, shell=True)
talk_is_not_installed = run_command.decode("utf-8")

if re.match("package talk is not installed", talk_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "telnet is not installed"
check_description = "-"

command = "sudo rpm -q telnet || true"
run_command = subprocess.check_output(command, shell=True)
telnet_is_not_installed = run_command.decode("utf-8")

if re.match("package telnet is not installed", telnet_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "LDAP Client is not installed"
check_description = "-"

command = "sudo rpm -q openldap-clients || true"
run_command = subprocess.check_output(command, shell=True)
openldap_clients_is_not_installed = run_command.decode("utf-8")

if re.match("package openldap-clients is not installed", openldap_clients_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Disable IPv6"
check_description = "-"

command = "sudo ip a | grep inet6 | wc -l || true"
run_command = subprocess.check_output(command, shell=True)
disable_ipv6 = run_command.decode("utf-8")

if re.match("0", disable_ipv6):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Disable wireless"
check_description = "Run this command to disable wireless: nmcli radio all off"

command = "sudo nmcli radio all | awk '{print $2 \" \" $4}' | tail -n +2"
run_command = subprocess.check_output(command, shell=True)
disable_wireless = run_command.decode("utf-8")

if re.match(".*disabled.*disabled", disable_wireless):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "IP forwarding is disabled"
check_description = "-"

command = "sudo sysctl net.ipv4.ip_forward"
run_command = subprocess.check_output(command, shell=True)
ip_forwarding_disabled = run_command.decode("utf-8")

if re.match("net.ipv4.ip_forward = 0", ip_forwarding_disabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Packet redirect sending is disabled"
check_description = "-"

command = "sudo sysctl net.ipv4.conf.all.send_redirects"
run_command = subprocess.check_output(command, shell=True)
packet_redirect_is_disabled_1 = run_command.decode("utf-8")

command = "sudo sysctl net.ipv4.conf.default.send_redirects"
run_command = subprocess.check_output(command, shell=True)
packet_redirect_is_disabled_2 = run_command.decode("utf-8")

if re.match("net.ipv4.conf.all.send_redirects = 0", packet_redirect_is_disabled_1) and re.match("net.ipv4.conf.default.send_redirects = 0", packet_redirect_is_disabled_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Source routed packets are not accepted"
check_description = "-"

command = "sudo sysctl net.ipv4.conf.all.accept_source_route"
run_command = subprocess.check_output(command, shell=True)
routed_packets_are_not_accept_1 = run_command.decode("utf-8")

command = "sudo sysctl net.ipv4.conf.default.accept_source_route"
run_command = subprocess.check_output(command, shell=True)
routed_packets_are_not_accept_2 = run_command.decode("utf-8")

if re.match("net.ipv4.conf.all.accept_source_route = 0", routed_packets_are_not_accept_1) and re.match("net.ipv4.conf.default.accept_source_route = 0", routed_packets_are_not_accept_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "ICMP redirects are not accepted"
check_description = "-"

command = "sudo sysctl net.ipv4.conf.all.accept_redirects"
run_command = subprocess.check_output(command, shell=True)
icmp_redirects_not_accepted_1 = run_command.decode("utf-8")

command = "sudo sysctl net.ipv4.conf.default.accept_redirects"
run_command = subprocess.check_output(command, shell=True)
icmp_redirects_not_accepted_2 = run_command.decode("utf-8")

if re.match("net.ipv4.conf.all.accept_redirects = 0", icmp_redirects_not_accepted_1) and re.match("net.ipv4.conf.default.accept_redirects = 0", icmp_redirects_not_accepted_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Secure ICMP redirects are not accepted"
check_description = "-"

command = "sudo sysctl net.ipv4.conf.all.secure_redirects"
run_command = subprocess.check_output(command, shell=True)
secure_icmp_redirects_not_accepted_1 = run_command.decode("utf-8")

command = "sudo sysctl net.ipv4.conf.default.secure_redirects"
run_command = subprocess.check_output(command, shell=True)
secure_icmp_redirects_not_accepted_2 = run_command.decode("utf-8")

if re.match("net.ipv4.conf.all.secure_redirects = 0", secure_icmp_redirects_not_accepted_1) and re.match("net.ipv4.conf.default.secure_redirects = 0", secure_icmp_redirects_not_accepted_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Suspicious packets are logged"
check_description = "-"

command = "sudo sysctl net.ipv4.conf.all.log_martians"
run_command = subprocess.check_output(command, shell=True)
suspicious_packets_are_logged_1 = run_command.decode("utf-8")

command = "sudo sysctl net.ipv4.conf.default.log_martians"
run_command = subprocess.check_output(command, shell=True)
suspicious_packets_are_logged_2 = run_command.decode("utf-8")

if re.match("net.ipv4.conf.all.log_martians = 1", suspicious_packets_are_logged_1) and re.match("net.ipv4.conf.default.log_martians = 1", suspicious_packets_are_logged_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Broadcast ICMP requests are ignored"
check_description = "-"

command = "sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts"
run_command = subprocess.check_output(command, shell=True)
broadcast_icmp_requests_are_ignored = run_command.decode("utf-8")

if re.match("net.ipv4.icmp_echo_ignore_broadcasts = 1", broadcast_icmp_requests_are_ignored):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Bogus ICMP responses are ignored"
check_description = "-"

command = "sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses"
run_command = subprocess.check_output(command, shell=True)
bogus_icmp_responses_ignored = run_command.decode("utf-8")

if re.match("net.ipv4.icmp_ignore_bogus_error_responses = 1", bogus_icmp_responses_ignored):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Reverse Path Filtering is enabled"
check_description = "-"

command = "sudo sysctl net.ipv4.conf.all.rp_filter"
run_command = subprocess.check_output(command, shell=True)
reverse_path_filtering_enabled_1 = run_command.decode("utf-8")

command = "sudo sysctl net.ipv4.conf.default.rp_filter"
run_command = subprocess.check_output(command, shell=True)
reverse_path_filtering_enabled_2 = run_command.decode("utf-8")

if re.match("net.ipv4.conf.all.rp_filter = 1", reverse_path_filtering_enabled_1) and re.match("net.ipv4.conf.default.rp_filter = 1", reverse_path_filtering_enabled_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "TCP SYN Cookies is enabled"
check_description = "-"

command = "sudo sysctl net.ipv4.tcp_syncookies"
run_command = subprocess.check_output(command, shell=True)
tcp_syn_cookies_enabled = run_command.decode("utf-8")

if re.match("net.ipv4.tcp_syncookies = 1", tcp_syn_cookies_enabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Firewalld is installed"
check_description = "-"

command = "sudo rpm -q firewalld 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
firewalld_installed_1 = run_command.decode("utf-8")

command = "sudo rpm -q iptables 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
firewalld_installed_2 = run_command.decode("utf-8")

if re.match("firewalld-", firewalld_installed_1) and re.match("iptables-", firewalld_installed_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "iptables-services not installed with firewalld"
check_description = "-"

command = "sudo rpm -q iptables-services 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
iptables_services_not_installed = run_command.decode("utf-8")

if re.match("package iptables-services is not installed", iptables_services_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "nftables not installed with firewalld"
check_description = "Page 261: Ensure nftables either not installed or masked with firewalld"

command = "sudo rpm -q nftables 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
nftables_not_installed = run_command.decode("utf-8")

if re.match("package nftables is not installed", nftables_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "firewalld service enabled and running"
check_description = "Page 263: Ensure firewalld service enabled and running"

command = "sudo systemctl is-enabled firewalld 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
firewalld_service_enabled_and_running_1 = run_command.decode("utf-8")

command = "sudo firewall-cmd --state 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
firewalld_service_enabled_and_running_2 = run_command.decode("utf-8")

if re.match("enabled", firewalld_service_enabled_and_running_1) and re.match("running", firewalld_service_enabled_and_running_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "firewalld default zone is set to public"
check_description = "Page 265: Ensure firewalld default zone is set"

command = "sudo firewall-cmd --get-default-zone 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
firewalld_default_zone_is_set = run_command.decode("utf-8")

if re.match("public", firewalld_default_zone_is_set):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Network interfaces are assigned to appropriate zone"
check_description = "Page 267: Ensure network interfaces are assigned to appropriate zone"

command = "sudo find /sys/class/net/* -maxdepth 1 | awk -F\"/\" '{print $NF}' | while read -r netint; do [ \"$netint\" != \"lo\" ] && firewall-cmd --get-active-zones | grep -B1 $netint; done || true"
run_command = subprocess.check_output(command, shell=True)
interface_zone_assigned = run_command.decode("utf-8")

if re.match("public\s.*interfaces:\s.*eth0", interface_zone_assigned):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "firewalld drops unnecessary services and ports"
check_description = "Page 269: Ensure firewalld drops unnecessary services and ports"

command = "sudo firewall-cmd --list-all --zone=public | grep services"
run_command = subprocess.check_output(command, shell=True)
interface_zone_assigned = run_command.decode("utf-8")

if re.match("\s*services:\s*dhcpv6-client\s*ssh", interface_zone_assigned):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Auditd is installed"
check_description = "Page 338: Ensure auditd is installed"

command = "sudo rpm -q audit || true"
run_command = subprocess.check_output(command, shell=True)
auditd_is_installed = run_command.decode("utf-8")

command = "sudo rpm -q audit-libs || true"
run_command = subprocess.check_output(command, shell=True)
audit_libs_is_installed = run_command.decode("utf-8")

if re.match("package audit is not installed", auditd_is_installed) and re.match("package audit-libs is not installed", audit_libs_is_installed):
    task_list.append([check_name, Failed, check_description])
else:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus


check_name = "auditd service is enabled and running"
check_description = "Page 340: Ensure auditd service is enabled and running"

command = "sudo systemctl is-enabled auditd 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
auditd_is_enabled = run_command.decode("utf-8")

command = "systemctl status auditd | grep 'Active: active (running) '"
run_command = subprocess.check_output(command, shell=True)
auditd_is_running = run_command.decode("utf-8")

if re.match("enabled", auditd_is_enabled) and re.match(".*(running).*", auditd_is_running):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "auditing for processes that start prior to auditd is enabled"
check_description = "Page 341: Ensure auditing for processes that start prior to auditd is enabled"

command = "sudo grep audit=1 /etc/default/grub 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
auditd_is_included_in_grub = run_command.decode("utf-8")

if re.match("GRUB_CMDLINE_LINUX.*audit=1.*", auditd_is_included_in_grub):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "rsyslog is installed"
check_description = "Page 395: Ensure rsyslog is installed"

command = "sudo rpm -q rsyslog || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_is_installed = run_command.decode("utf-8")

if re.match("package rsyslog is not installed", rsyslog_is_installed):
    task_list.append([check_name, Failed, check_description])
else:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus


check_name = "rsyslog service is enabled and running"
check_description = "Page 397: Ensure rsyslog Service is enabled and running"

command = "sudo systemctl is-enabled rsyslog 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_is_enabled = run_command.decode("utf-8")

command = "systemctl status rsyslog | grep 'Active: active (running) '"
run_command = subprocess.check_output(command, shell=True)
rsyslog_is_running = run_command.decode("utf-8")

if re.match("enabled", rsyslog_is_enabled) and re.match(".*(running).*", rsyslog_is_running):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "rsyslog default file permissions configured"
check_description = "Page 399: Ensure rsyslog default file permissions configured"

command = "sudo grep ^\$FileCreateMode /etc/rsyslog.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_default_permissions = run_command.decode("utf-8")

if re.match(".*\s0640", rsyslog_default_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "rsyslog is configured to send logs to a remote log host"
check_description = "Page 403: Ensure rsyslog is configured to send logs to a remote log host"

command = "sudo grep -G \"^authpriv.*\" /etc/rsyslog.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_remote_server = run_command.decode("utf-8")

if re.match("authpriv.* @192.168.214.62", rsyslog_remote_server) or re.match("authpriv.* @192.168.213.40", rsyslog_remote_server):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 406: Ensure remote rsyslog messages are only accepted on designated log hosts"
check_description = "-"

command = "sudo grep '$ModLoad imtcp' /etc/rsyslog.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_is_not_accepting_logs_1 = run_command.decode("utf-8")

command = "sudo grep '$InputTCPServerRun' /etc/rsyslog.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_is_not_accepting_logs_2 = run_command.decode("utf-8")

if re.match("^#\$ModLoad imtcp", rsyslog_is_not_accepting_logs_1) and re.match("^#\$InputTCPServerRun 514", rsyslog_is_not_accepting_logs_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 409: Ensure journald is configured to send logs to rsyslog"
check_description = "-"

command = "sudo grep -G \"^ForwardToSyslog\" /etc/systemd/journald.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
journald_logs_to_rsyslog = run_command.decode("utf-8")

if re.match("^ForwardToSyslog=yes", journald_logs_to_rsyslog):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 411: Ensure journald is configured to compress large log files"
check_description = "-"

command = "sudo grep Compress /etc/systemd/journald.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
journald_compress = run_command.decode("utf-8")

if re.match("^Compress=yes", journald_compress):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 413: Ensure journald is configured to write logfiles to persistent disk"
check_description = "-"

command = "sudo grep Storage /etc/systemd/journald.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
journald_persistent_storage = run_command.decode("utf-8")

if re.match("^Storage=persistent", journald_persistent_storage):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 415: Ensure permissions on all logfiles are configured"
check_description = "-"

command = "sudo find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \; | wc -l 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
log_files_permissions = run_command.decode("utf-8")

if re.match("0", log_files_permissions):
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
print(" - Check if xorg server components are needed. Page 163.")
print(" - Check if cups is needed. Page 167.")
print(" - Check if rpcbind is needed. Page 196.")
print()