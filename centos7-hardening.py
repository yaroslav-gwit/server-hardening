#!/usr/bin/env python3
# native imports
from asyncio.subprocess import DEVNULL
import subprocess
import argparse
import re
from os.path import exists

# 3rd party imports
from colorama import Fore, Back, Style
from tabulate import tabulate

# Bold table headers
bolded_string_Task = "\033[1m" + "Task name" + "\033[0m"
bolded_string_Status = "\033[1m" + "Status" + "\033[0m"
bolded_string_Details = "\033[1m" + "Details" + "\033[0m"
bloded_string_TotalScore = "\033[1m" + "Total System Hardening Points" + "\033[0m"

# Score values
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
check_name = "Page 21: Ensure mounting of cramfs filesystems is disabled"
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


check_name = "Page 25: Ensure mounting of udf filesystems is disabled"
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


check_name = "Page 27: Ensure /tmp is configured"
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


check_name = "Page 31: Ensure noexec option set on /tmp partition"
check_description = "-"
command = "sudo findmnt -n /tmp | grep -c -Ev '\\bnoexec\\b' || true"
run_command = subprocess.check_output(command, shell=True)
tmp_noexec_mount_check = run_command.decode("utf-8")

if re.match("0", tmp_noexec_mount_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 33: Ensure nodev option set on /tmp partition"
check_description = "-"
command = "sudo findmnt -n /tmp | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
tmp_nodev_mount_check = run_command.decode("utf-8")

if re.match("0", tmp_nodev_mount_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 35: Ensure nosuid option set on /tmp partition"
check_description = "-"
command = "sudo findmnt -n /tmp | grep -c -Ev '\\bnosuid\\b' || true"
run_command = subprocess.check_output(command, shell=True)
tmp_nosuid_mount_check = run_command.decode("utf-8")

if re.match("0", tmp_nosuid_mount_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 37: Ensure /dev/shm is configured "
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


check_name = "Page 39: Ensure noexec option set on /dev/shm partition"
check_description = "-"
command = "sudo findmnt -n /dev/shm | grep -c -Ev '\\bnoexec\\b' || true"
run_command = subprocess.check_output(command, shell=True)
devshm_mount_noexec_check = run_command.decode("utf-8")

if re.match("0", devshm_mount_noexec_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 41: Ensure nodev option set on /dev/shm partition "
check_description = "-"
command = "sudo findmnt -n /dev/shm | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
devshm_mount_nodev_check = run_command.decode("utf-8")

if re.match("0", devshm_mount_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 43: Ensure nosuid option set on /dev/shm partition"
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
check_name = "Page 45: Ensure separate partition exists for /var"
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
check_name = "Page 47: Ensure separate partition exists for /var/tmp"
check_description = "-"
command = "sudo findmnt /var/tmp | wc -l"
run_command = subprocess.check_output(command, shell=True)
vartmp_partition_check = run_command.decode("utf-8")

if re.match("[^0]", vartmp_partition_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 49: Ensure /var/tmp partition includes the noexec option"
check_description = "-"
command = "sudo findmnt -n /var/tmp | grep -c -Ev '\\bnoexec\\b' || true"
run_command = subprocess.check_output(command, shell=True)
vartmp_noexec_check = run_command.decode("utf-8")

if re.match("0", vartmp_noexec_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 51: Ensure /var/tmp partition includes the nodev option"
check_description = "-"
command = "sudo findmnt -n /var/tmp | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
vartmp_nodev_check = run_command.decode("utf-8")

if re.match("0", vartmp_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 53: Ensure /var/tmp partition includes the nosuid option"
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
check_name = "Page 55: Ensure separate partition exists for /var/log"
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
check_name = "Page 57: Ensure separate partition exists for /var/log/audit"
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
check_name = "Page 59: Ensure separate partition exists for /home"
check_description = "-"
command = "sudo findmnt /home | wc -l"
run_command = subprocess.check_output(command, shell=True)
home_partition_check = run_command.decode("utf-8")

if re.match("[^0]", home_partition_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 61: Ensure /home partition includes the nodev option"
check_description = "-"
command = "sudo findmnt -n /home | grep -c -Ev '\\bnodev\\b' || true"
run_command = subprocess.check_output(command, shell=True)
home_nodev_check = run_command.decode("utf-8")

if re.match("0", home_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 63: Ensure removable media partitions include noexec option"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_removable_drives_noexec.sh | wc -l"
run_command = subprocess.check_output(command, shell=True)
rem_media_noexec_check = run_command.decode("utf-8")

if re.match("0", rem_media_noexec_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 65: Ensure nodev option set on removable media partitions"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_removable_drives_nodev.sh | wc -l"
run_command = subprocess.check_output(command, shell=True)
rem_media_nodev_check = run_command.decode("utf-8")

if re.match("0", rem_media_nodev_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 67: Ensure nosuid option set on removable media partitions"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_removable_drives_suid.sh | wc -l"
run_command = subprocess.check_output(command, shell=True)
rem_media_nosuid_check = run_command.decode("utf-8")

if re.match("0", rem_media_nosuid_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 69: Ensure sticky bit is set on all world-writable directories"
check_description = "-"
command = "sudo df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | wc -l"
run_command = subprocess.check_output(command, shell=True)
sticky_bit_check = run_command.decode("utf-8")

if re.match("0", sticky_bit_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 71: Disable Automounting"
check_description = "-"
command = "sudo systemctl show \"autofs.service\" | grep -i unitfilestate=enabled | wc -l"
run_command = subprocess.check_output(command, shell=True)
disable_automounting = run_command.decode("utf-8")

if re.match("0", disable_automounting):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 73: Disable USB Storage"
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


check_name = "Page 80: Ensure gpgcheck is globally activated"
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


check_name = "Page 83: Ensure AIDE is installed"
check_description = "-"
command = "sudo rpm -q aide || true"
run_command = subprocess.check_output(command, shell=True)
aide_is_installed = run_command.decode("utf-8")

if re.match("package aide is not installed", aide_is_installed):
    task_list.append([check_name, Failed, check_description])
else:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus


check_name = "Page 85: Ensure filesystem integrity is regularly checked"
check_description = "Logs are kept in /root/aide_log_<date>.log"
command = "sudo grep -c aide /etc/crontab || true"
run_command = subprocess.check_output(command, shell=True)
aide_is_scheduled = run_command.decode("utf-8")

if re.match("^[0]", aide_is_scheduled):
    task_list.append([check_name, Failed, check_description])
else:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus


check_name = "Page 89: Ensure bootloader password is set"
check_description = "-"
command = "sudo " + bash_scripts_location + "check_bootloader_password.sh"
run_command = subprocess.check_output(command, shell=True)
grub2_is_password_protected = run_command.decode("utf-8")

if re.match("1", grub2_is_password_protected):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 93: Ensure permissions on bootloader config are configured"
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


check_name = "Page 96: Ensure authentication required for single user mode"
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


check_name = "Page 99: Ensure core dumps are restricted"
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


check_name = "Page 101: Ensure XD/NX support is enabled"
check_description = "-"
command = "sudo journalctl | grep 'protection: active'"
run_command = subprocess.check_output(command, shell=True)
xd_nx_support_enabled = run_command.decode("utf-8")

if re.match(".*protection: active.*", xd_nx_support_enabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 103: Ensure address space layout randomization (ASLR) is enabled"
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


check_name = "Page 105: Ensure prelink is not installed"
check_description = "-"

command = "sudo rpm -q prelink || true"
run_command = subprocess.check_output(command, shell=True)
prelink_is_not_installed = run_command.decode("utf-8")

if re.match("package prelink is not installed", prelink_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 109: Ensure SELinux is installed"
check_description = "-"

command = "sudo rpm -q libselinux || true"
run_command = subprocess.check_output(command, shell=True)
selinux_is_installed = run_command.decode("utf-8")

if re.match("libselinux-.*", selinux_is_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 111: Ensure SELinux is not disabled in bootloader configuration"
check_description = "-"

command = "sudo grep -Eq \"(selinux=0|enforcing=0)\" /boot/efi/EFI/centos/grub.cfg | wc -l || true"
run_command = subprocess.check_output(command, shell=True)
selinux_is_not_disabled_in_grubcfg = run_command.decode("utf-8")

if re.match("0", selinux_is_not_disabled_in_grubcfg):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 113: Ensure SELinux policy is configured"
check_description = "-"

command = "sudo grep -G \"^SELINUXTYPE=\" /etc/selinux/config || true"
run_command = subprocess.check_output(command, shell=True)
selinux_policy_is_configured = run_command.decode("utf-8")

if re.match("SELINUXTYPE=targeted", selinux_policy_is_configured):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 115: Ensure the SELinux mode is enforcing or permissive"
check_description = "We are running SELinux mostly in permissive mode"

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


check_name = "Page 120: Ensure no unconfined services exist"
check_description = "-"

command = "sudo ps -eZ | grep unconfined_service_t | wc -l"
run_command = subprocess.check_output(command, shell=True)
unconfigured_services_check = run_command.decode("utf-8")

if re.match("0", unconfigured_services_check):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 122: Ensure SETroubleshoot is not installed"
check_description = "-"

command = "sudo rpm -q setroubleshoot || true"
run_command = subprocess.check_output(command, shell=True)
setroubleshoot_is_not_installed = run_command.decode("utf-8")

if re.match("package setroubleshoot is not installed", setroubleshoot_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 124: Ensure the MCS Translation Service (mcstrans) is not installed"
check_description = "-"

command = "sudo rpm -q mcstrans || true"
run_command = subprocess.check_output(command, shell=True)
mcstrans_is_not_installed = run_command.decode("utf-8")

if re.match("package mcstrans is not installed", mcstrans_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 127: Ensure message of the day is configured properly"
check_description = "-"
command = "sudo grep \"UNAUTHORISED ACCESS TO THIS APPLIANCE IS PROHIBITED\" /etc/motd | wc -l"
run_command = subprocess.check_output(command, shell=True)
motd_is_configued = run_command.decode("utf-8")

if re.match("1", motd_is_configued):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 129: Ensure local login warning banner is configured properly"
check_description = "-"
command = "sudo grep \"UNAUTHORISED ACCESS TO THIS APPLIANCE IS PROHIBITED\" /etc/issue | wc -l"
run_command = subprocess.check_output(command, shell=True)
etc_issue_is_configured = run_command.decode("utf-8")

if re.match("1", etc_issue_is_configured):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 131: Ensure remote login warning banner is configured properly"
check_description = "-"
command = "sudo grep \"UNAUTHORISED ACCESS TO THIS APPLIANCE IS PROHIBITED\" /etc/issue.net | wc -l"
run_command = subprocess.check_output(command, shell=True)
etc_issue_net_is_configured = run_command.decode("utf-8")

if re.match("1", etc_issue_net_is_configured):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 133: Ensure permissions on /etc/motd are configured"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/motd\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_motd = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_motd):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 135: Ensure permissions on /etc/issue are configured"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/issue\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_issue = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_issue):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 137: Ensure permissions on /etc/issue.net are configured"
check_description = "-"
command = "sudo stat -c \"%a\" \"/etc/issue.net\""
run_command = subprocess.check_output(command, shell=True)
permissions_on_etc_issue_net = run_command.decode("utf-8")

if re.match("644", permissions_on_etc_issue_net):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 140: Ensure GNOME Display Manager is removed"
check_description = "-"

command = "sudo rpm -q gdm || true"
run_command = subprocess.check_output(command, shell=True)
gdm_is_not_installed = run_command.decode("utf-8")

if re.match("package gdm is not installed", gdm_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])#


check_name = "Page 146: Ensure XDCMP is not enabled"
check_description = "-"

command = "sudo grep -Eis '^\\s*Enable\\s*=\\s*true' /etc/gdm/custom.conf | wc -l"
run_command = subprocess.check_output(command, shell=True)
xdcmp_is_not_enabled = run_command.decode("utf-8")

if re.match("0", xdcmp_is_not_enabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 152: Ensure xinetd is not installed"
check_description = "-"

command = "sudo rpm -q xinetd || true"
run_command = subprocess.check_output(command, shell=True)
xinetd_is_not_installed = run_command.decode("utf-8")

if re.match("package xinetd is not installed", xinetd_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 156: Ensure time synchronization is in use"
check_description = "This check shows if chrony is installed"

command = "sudo rpm -q chrony || true"
run_command = subprocess.check_output(command, shell=True)
chrony_is_installed = run_command.decode("utf-8")

if re.match("chrony-", chrony_is_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 158: Ensure chrony is configured"
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


check_name = "Page 163: Ensure X11 Server components are not installed"
check_description = "Some xorg packages are required by ICR staff"

command = "sudo rpm -qa xorg-x11-server* | wc -l || true"
run_command = subprocess.check_output(command, shell=True)
xorg_is_not_installed = run_command.decode("utf-8")

if re.match("0", xorg_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 165: Ensure Avahi Server is not installed"
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


check_name = "Page 167: Ensure CUPS is not installed"
check_description = "CUPS is a dependency for Samba"

command = "sudo rpm -q cups || true"
run_command = subprocess.check_output(command, shell=True)
cups_is_not_installed = run_command.decode("utf-8")

if re.match("package avahi-autoipd is not installed", cups_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 169: Ensure DHCP Server is not installed"
check_description = "-"

command = "sudo rpm -q dhcp || true"
run_command = subprocess.check_output(command, shell=True)
dhcp_server_is_not_installed = run_command.decode("utf-8")

if re.match("package dhcp is not installed", dhcp_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 171: Ensure LDAP server is not installed"
check_description = "-"

command = "sudo rpm -q openldap-servers || true"
run_command = subprocess.check_output(command, shell=True)
ldap_server_is_not_installed = run_command.decode("utf-8")

if re.match("package openldap-servers is not installed", ldap_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 173: Ensure DNS Server is not installed"
check_description = "-"

command = "sudo rpm -q bind || true"
run_command = subprocess.check_output(command, shell=True)
dns_server_is_not_installed = run_command.decode("utf-8")

if re.match("package bind is not installed", dns_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 175: Ensure FTP Server is not installed "
check_description = "-"

command = "sudo rpm -q vsftpd || true"
run_command = subprocess.check_output(command, shell=True)
ftp_server_is_not_installed = run_command.decode("utf-8")

if re.match("package vsftpd is not installed", ftp_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 177: Ensure HTTP server is not installed"
check_description = "This only checks if Apache is installed (for now)"

command = "sudo rpm -q httpd || true"
run_command = subprocess.check_output(command, shell=True)
httpd_server_is_not_installed = run_command.decode("utf-8")

if re.match("package httpd is not installed", httpd_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 179: Ensure IMAP and POP3 server is not installed "
check_description = "-"

command = "sudo rpm -q dovecot || true"
run_command = subprocess.check_output(command, shell=True)
dovecot_server_is_not_installed = run_command.decode("utf-8")

if re.match("package dovecot is not installed", dovecot_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 181: Ensure Samba is not installed"
check_description = "Samba is required by ICR staff to access shared folders"

command = "sudo rpm -q samba || true"
run_command = subprocess.check_output(command, shell=True)
samba_is_not_installed = run_command.decode("utf-8")

if re.match("package samba is not installed", samba_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 183: Ensure HTTP Proxy Server is not installed"
check_description = "-"

command = "sudo rpm -q squid || true"
run_command = subprocess.check_output(command, shell=True)
squid_is_not_installed = run_command.decode("utf-8")

if re.match("package squid is not installed", squid_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 185: Ensure net-snmp is not installed"
check_description = "-"

command = "sudo rpm -q net-snmp || true"
run_command = subprocess.check_output(command, shell=True)
net_snmp_is_not_installed = run_command.decode("utf-8")

if re.match("package net-snmp is not installed", net_snmp_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 187: Ensure NIS server is not installed"
check_description = "-"

command = "sudo rpm -q ypserv || true"
run_command = subprocess.check_output(command, shell=True)
ypserv_is_not_installed = run_command.decode("utf-8")

if re.match("package ypserv is not installed", ypserv_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 189: Ensure telnet-server is not installed "
check_description = "-"

command = "sudo rpm -q telnet-server || true"
run_command = subprocess.check_output(command, shell=True)
telnet_server_is_not_installed = run_command.decode("utf-8")

if re.match("package telnet-server is not installed", telnet_server_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 191: Ensure mail transfer agent is configured for local-only mode"
check_description = "-"

command = "sudo ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s' | wc -l"
run_command = subprocess.check_output(command, shell=True)
mta_local_only_mode = run_command.decode("utf-8")

if re.match("0", mta_local_only_mode):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 193: Ensure nfs-utils is not installed or the nfs-server service is masked"
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


check_name = "Page 195: Ensure rpcbind is not installed or the rpcbind services are masked"
check_description = "This check is expected to fail because of samba dependency"

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


check_name = "Page 198: Ensure rsync is not installed or the rsyncd service is masked"
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


check_name = "Page 201: Ensure NIS Client is not installed"
check_description = "-"

command = "sudo rpm -q ypbind || true"
run_command = subprocess.check_output(command, shell=True)
ypbind_is_not_installed = run_command.decode("utf-8")

if re.match("package ypbind is not installed", ypbind_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 203: Ensure rsh client is not installed"
check_description = "-"

command = "sudo rpm -q rsh || true"
run_command = subprocess.check_output(command, shell=True)
rsh_is_not_installed = run_command.decode("utf-8")

if re.match("package rsh is not installed", rsh_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 205: Ensure talk client is not installed"
check_description = "-"

command = "sudo rpm -q talk || true"
run_command = subprocess.check_output(command, shell=True)
talk_is_not_installed = run_command.decode("utf-8")

if re.match("package talk is not installed", talk_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 207: Ensure telnet client is not installed"
check_description = "-"

command = "sudo rpm -q telnet || true"
run_command = subprocess.check_output(command, shell=True)
telnet_is_not_installed = run_command.decode("utf-8")

if re.match("package telnet is not installed", telnet_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 209: Ensure LDAP client is not installed"
check_description = "-"

command = "sudo rpm -q openldap-clients || true"
run_command = subprocess.check_output(command, shell=True)
openldap_clients_is_not_installed = run_command.decode("utf-8")

if re.match("package openldap-clients is not installed", openldap_clients_is_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 215: Disable IPv6"
check_description = "-"

command = "sudo ip a | grep inet6 | wc -l || true"
run_command = subprocess.check_output(command, shell=True)
disable_ipv6 = run_command.decode("utf-8")

if re.match("0", disable_ipv6):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 218: Ensure wireless interfaces are disabled"
check_description = "Run this command to disable wireless: nmcli radio all off"

command = "sudo nmcli radio all | awk '{print $2 \" \" $4}' | tail -n +2"
run_command = subprocess.check_output(command, shell=True)
disable_wireless = run_command.decode("utf-8")

if re.match(".*disabled.*disabled", disable_wireless):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 222: Ensure IP forwarding is disabled"
check_description = "-"

command = "sudo sysctl net.ipv4.ip_forward"
run_command = subprocess.check_output(command, shell=True)
ip_forwarding_disabled = run_command.decode("utf-8")

if re.match("net.ipv4.ip_forward = 0", ip_forwarding_disabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 225: Ensure packet redirect sending is disabled"
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


check_name = "Page 228: Ensure source routed packets are not accepted"
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


check_name = "Page 232: Ensure ICMP redirects are not accepted"
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


check_name = "Page 235: Ensure secure ICMP redirects are not accepted"
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


check_name = "Page 237: Ensure suspicious packets are logged"
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


check_name = "Page 239: Ensure broadcast ICMP requests are ignored"
check_description = "-"

command = "sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts"
run_command = subprocess.check_output(command, shell=True)
broadcast_icmp_requests_are_ignored = run_command.decode("utf-8")

if re.match("net.ipv4.icmp_echo_ignore_broadcasts = 1", broadcast_icmp_requests_are_ignored):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 241: Ensure bogus ICMP responses are ignored"
check_description = "-"

command = "sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses"
run_command = subprocess.check_output(command, shell=True)
bogus_icmp_responses_ignored = run_command.decode("utf-8")

if re.match("net.ipv4.icmp_ignore_bogus_error_responses = 1", bogus_icmp_responses_ignored):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 243: Ensure Reverse Path Filtering is enabled"
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


check_name = "Page 245: Ensure TCP SYN Cookies is enabled"
check_description = "-"

command = "sudo sysctl net.ipv4.tcp_syncookies"
run_command = subprocess.check_output(command, shell=True)
tcp_syn_cookies_enabled = run_command.decode("utf-8")

if re.match("net.ipv4.tcp_syncookies = 1", tcp_syn_cookies_enabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 257: Ensure firewalld is installed"
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


check_name = "Page 259: Ensure iptables-services not installed with firewalld"
check_description = "-"

command = "sudo rpm -q iptables-services 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
iptables_services_not_installed = run_command.decode("utf-8")

if re.match("package iptables-services is not installed", iptables_services_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 261: Ensure nftables either not installed or masked with firewalld"
check_description = "-"

command = "sudo rpm -q nftables 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
nftables_not_installed = run_command.decode("utf-8")

if re.match("package nftables is not installed", nftables_not_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 263: Ensure firewalld service enabled and running"
check_description = "-"

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


check_name = "Page 265: Ensure firewalld default zone is set"
check_description = "-"

command = "sudo firewall-cmd --get-default-zone 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
firewalld_default_zone_is_set = run_command.decode("utf-8")

if re.match("public", firewalld_default_zone_is_set):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 267: Ensure network interfaces are assigned to appropriate zone"
check_description = "-"

command = "sudo find /sys/class/net/* -maxdepth 1 | awk -F\"/\" '{print $NF}' | while read -r netint; do [ \"$netint\" != \"lo\" ] && firewall-cmd --get-active-zones | grep -B1 $netint; done || true"
run_command = subprocess.check_output(command, shell=True)
interface_zone_assigned = run_command.decode("utf-8")

if re.match("public\s.*interfaces:\s.*eth0", interface_zone_assigned):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 269: Ensure firewalld drops unnecessary services and ports"
check_description = "-"

command = "sudo firewall-cmd --list-all --zone=public | grep services"
run_command = subprocess.check_output(command, shell=True)
interface_zone_assigned = run_command.decode("utf-8")

if re.match("\s*services:\s*dhcpv6-client\s*ssh", interface_zone_assigned):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 338: Ensure auditd is installed"
check_description = "-"

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


check_name = "Page 340: Ensure auditd service is enabled and running"
check_description = "-"

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


check_name = "Page 341: Ensure auditing for processes that start prior to auditd is enabled"
check_description = "-"

command = "sudo grep audit=1 /etc/default/grub 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
auditd_is_included_in_grub = run_command.decode("utf-8")

if re.match("GRUB_CMDLINE_LINUX.*audit=1.*", auditd_is_included_in_grub):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl2_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 395: Ensure rsyslog is installed"
check_description = "-"

command = "sudo rpm -q rsyslog || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_is_installed = run_command.decode("utf-8")

if re.match("package rsyslog is not installed", rsyslog_is_installed):
    task_list.append([check_name, Failed, check_description])
else:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus


check_name = "Page 397: Ensure rsyslog Service is enabled and running"
check_description = "-"

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


check_name = "Page 399: Ensure rsyslog default file permissions configured"
check_description = "-"

command = "sudo grep ^\$FileCreateMode /etc/rsyslog.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
rsyslog_default_permissions = run_command.decode("utf-8")

if re.match(".*\s0640", rsyslog_default_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 403: Ensure rsyslog is configured to send logs to a remote log host"
check_description = "-"

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


check_name = "Page 417: Ensure logrotate is configured"
check_description = "-"

command = "sudo grep -G \"^weekly\" /etc/logrotate.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
logrotate_is_configured = run_command.decode("utf-8")

if re.match("weekly", logrotate_is_configured):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 421: Ensure cron daemon is enabled and running"
check_description = "-"

command = "sudo systemctl is-enabled crond 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
crond_is_enabled = run_command.decode("utf-8")

command = "sudo systemctl status crond | grep Active 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
crond_is_running = run_command.decode("utf-8")

if re.match("enabled", crond_is_enabled) and re.match(".*Active: active \(running\).*", crond_is_running):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 423: Ensure permissions on /etc/crontab are configured"
check_description = "-"

command = "sudo stat /etc/crontab | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
crontab_permissions = run_command.decode("utf-8")

if re.match(".*0600.*root.*root", crontab_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 425: Ensure permissions on /etc/cron.hourly are configured"
check_description = "-"

command = "sudo stat /etc/cron.hourly/ | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
cron_hourly_folder_permissions = run_command.decode("utf-8")

if re.match(".*0700.*root.*root", cron_hourly_folder_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 427: Ensure permissions on /etc/cron.daily are configured"
check_description = "-"

command = "sudo stat /etc/cron.daily/ | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
cron_daily_folder_permissions = run_command.decode("utf-8")

if re.match(".*0700.*root.*root", cron_daily_folder_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 429: Ensure permissions on /etc/cron.weekly are configured"
check_description = "-"

command = "sudo stat /etc/cron.weekly/ | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
cron_weekly_folder_permissions = run_command.decode("utf-8")

if re.match(".*0700.*root.*root", cron_weekly_folder_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 431: Ensure permissions on /etc/cron.monthly are configured"
check_description = "-"

command = "sudo stat /etc/cron.monthly/ | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
cron_monthly_folder_permissions = run_command.decode("utf-8")

if re.match(".*0700.*root.*root", cron_monthly_folder_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 433: Ensure permissions on /etc/cron.d are configured"
check_description = "-"

command = "sudo stat /etc/cron.d/ | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
cron_d_folder_permissions = run_command.decode("utf-8")

if re.match(".*0700.*root.*root", cron_d_folder_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 435: Ensure cron is restricted to authorized users"
check_description = "-"

cron_deny_exist = exists("/etc/cron.deny")
cron_allow_exist = exists("/etc/cron.allow")

command = "sudo stat /etc/cron.allow | grep \"Access: (\" 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
cron_allow_permissions = run_command.decode("utf-8")

if not cron_deny_exist and cron_allow_exist and re.match(".*0600.*root.*root", cron_allow_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 437: Ensure at is restricted to authorized users"
check_description = "-"

at_deny_exist = exists("/etc/at.deny")
at_allow_exist = exists("/etc/at.allow")

command = "sudo stat /etc/at.allow | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
at_allow_permissions = run_command.decode("utf-8")

if not at_deny_exist and at_allow_exist and re.match(".*0600.*root.*root", at_allow_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 440: Ensure sudo is installed"
check_description = "-"

command = "rpm -q sudo 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
sudo_is_installed = run_command.decode("utf-8")

if re.match("sudo-.*", sudo_is_installed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 442: Ensure sudo commands use pty"
check_description = "-"

command = "sudo grep use_pty /etc/sudoers 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
sudo_uses_pty = run_command.decode("utf-8")

if re.match("Defaults use_pty", sudo_uses_pty):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 444: Ensure sudo log file exists"
check_description = "-"

sudo_log_file_exists = exists("/var/log/sudo.log")

command = "sudo grep logfile /etc/sudoers 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
sudo_log_file_config = run_command.decode("utf-8")

if sudo_log_file_exists and re.match("Defaults logfile=\"/var/log/sudo.log\"", sudo_log_file_config):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 447: Ensure permissions on /etc/ssh/sshd_config are configured"
check_description = "-"

command = "sudo stat /etc/ssh/sshd_config | grep Access | head -1 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
ssh_config_permissions = run_command.decode("utf-8")

if re.match(".*0600.*root.*root", ssh_config_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 449: Ensure permissions on SSH private host key files are configured"
check_description = "-"

command = "sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True)
ssh_host_key_files_permissions = run_command.decode("utf-8")

if re.match(".*0600.*root.*root.*", ssh_host_key_files_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 452: Ensure permissions on SSH public host key files are configured"
check_description = "-"

command = "sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True)
ssh_host_pubkey_files_permissions = run_command.decode("utf-8")

if re.match(".*0644.*root.*root.*", ssh_host_pubkey_files_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 458: Ensure SSH LogLevel is appropriate"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep loglevel"
run_command = subprocess.check_output(command, shell=True)
ssh_log_level_1 = run_command.decode("utf-8")

command = "sudo grep -i 'loglevel' /etc/ssh/sshd_config | grep -Ei '(VERBOSE|INFO)'"
run_command = subprocess.check_output(command, shell=True)
ssh_log_level_2 = run_command.decode("utf-8")

ssh_log_level_re = ".*VERBOSE|.*INFO"

if re.match(ssh_log_level_re, ssh_log_level_1) and re.match(ssh_log_level_re, ssh_log_level_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 462: Ensure SSH MaxAuthTries is set to 4 or less"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep maxauthtries"
run_command = subprocess.check_output(command, shell=True)
ssh_maxauthtries_1 = run_command.decode("utf-8").split()[1]

command = "sudo grep -Gi \"^maxauthtries\" /etc/ssh/sshd_config 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
ssh_maxauthtries_2 = run_command.decode("utf-8").split()[1]

if int(ssh_maxauthtries_1) <= 4 and int(ssh_maxauthtries_2) <= 4:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 464: Ensure SSH IgnoreRhosts is enabled"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep ignorerhosts"
run_command = subprocess.check_output(command, shell=True)
ssh_ignore_rhosts_1 = run_command.decode("utf-8")

command = "sudo grep -Gi \"^ignorerhosts\" /etc/ssh/sshd_config 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
ssh_ignore_rhosts_2 = run_command.decode("utf-8")

ssh_ignore_rhosts_re = "[Ii]gnore[Rr]hosts yes"

if re.match(ssh_ignore_rhosts_re, ssh_ignore_rhosts_1) and re.match(ssh_ignore_rhosts_re, ssh_ignore_rhosts_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 466: Ensure SSH HostbasedAuthentication is disabled"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep hostbasedauthentication"
run_command = subprocess.check_output(command, shell=True)
ssh_host_based_auth_1 = run_command.decode("utf-8")

command = "sudo grep -Gi \"^hostbased\" /etc/ssh/sshd_config 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
ssh_host_based_auth_2 = run_command.decode("utf-8")

ssh_host_based_auth_re = "[Hh]ostbased[Aa]uthentication no"

if re.match(ssh_host_based_auth_re, ssh_host_based_auth_1) and re.match(ssh_host_based_auth_re, ssh_host_based_auth_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 468: Ensure SSH root login is disabled"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep permitrootlogin"
run_command = subprocess.check_output(command, shell=True)
ssh_permit_root_login_1 = run_command.decode("utf-8")

command = "sudo grep -Gi \"^permitrootlogin\" /etc/ssh/sshd_config 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
ssh_permit_root_login_2 = run_command.decode("utf-8")

ssh_permit_root_login_re = "[Pp]ermit[Rr]oot[Ll]ogin no"

if re.match(ssh_permit_root_login_re, ssh_permit_root_login_1) and re.match(ssh_permit_root_login_re, ssh_permit_root_login_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 470: Ensure SSH PermitEmptyPasswords is disabled"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep permitemptypasswords"
run_command = subprocess.check_output(command, shell=True)
ssh_permit_empty_passwords_1 = run_command.decode("utf-8")

command = "sudo grep -Gi \"^permitemptypasswords\" /etc/ssh/sshd_config 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
ssh_permit_empty_passwords_2 = run_command.decode("utf-8")

ssh_permit_empty_passwords_re = "[Pp]ermit[Ee]mpty[Pp]asswords no"

if re.match(ssh_permit_empty_passwords_re, ssh_permit_empty_passwords_1) and re.match(ssh_permit_empty_passwords_re, ssh_permit_empty_passwords_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 472: Ensure SSH PermitUserEnvironment is disabled"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep permituserenvironment"
run_command = subprocess.check_output(command, shell=True)
ssh_permit_user_environment_1 = run_command.decode("utf-8")

command = "sudo grep -Gi \"^permituserenvironment\" /etc/ssh/sshd_config 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
ssh_permit_user_environment_2 = run_command.decode("utf-8")

ssh_permit_user_environment_re = "[Pp]ermit[Uu]ser[Ee]nvironment no"

if re.match(ssh_permit_user_environment_re, ssh_permit_user_environment_1) and re.match(ssh_permit_user_environment_re, ssh_permit_user_environment_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 474: Ensure only strong Ciphers are used"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep -Ei '^\\s*ciphers\\s+([^#]+,)?(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator.liu.se)\\b' | wc -l"
run_command = subprocess.check_output(command, shell=True)
ssh_only_strong_ciphers = run_command.decode("utf-8")

ssh_only_strong_ciphers_re = "0"

if re.match(ssh_only_strong_ciphers_re, ssh_only_strong_ciphers):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 477: Ensure only strong MAC algorithms are used"
check_description = "-"

command = "sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep -Ei '^\\s*macs\\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh\\.com|hmac-md5-etm@openssh\\.com|hmac-md5-96-etm@openssh\\.com|hmac-ripemd160-etm@openssh\\.com|hmac-sha1-etm@openssh\\.com|hmac-sha1-96-etm@openssh\\.com|umac-64-etm@openssh\\.com|umac-128-etm@openssh\\.com)\\b' | wc -l"
run_command = subprocess.check_output(command, shell=True)
ssh_only_strong_macs = run_command.decode("utf-8")

ssh_only_strong_macs_re = "0"

if re.match(ssh_only_strong_macs_re, ssh_only_strong_macs):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 481: Ensure only strong Key Exchange algorithms are used"
check_description = "-"

command = "sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep -Ei '^\\s*kexalgorithms\\s+([^#]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\\b' | wc -l"
run_command = subprocess.check_output(command, shell=True)
ssh_only_strong_key_exchanges = run_command.decode("utf-8")

ssh_only_strong_key_exchanges_re = "0"

if re.match(ssh_only_strong_key_exchanges_re, ssh_only_strong_key_exchanges):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 484: Ensure SSH Idle Timeout Interval is configured"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep clientaliveinterval"
run_command = subprocess.check_output(command, shell=True)
ssh_idle_timeout_interval_1 = run_command.decode("utf-8").split()[1]

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep clientalivecountmax"
run_command = subprocess.check_output(command, shell=True)
ssh_idle_timeout_interval_2 = run_command.decode("utf-8").split()[1]

if int(ssh_idle_timeout_interval_1) >= 1 and int(ssh_idle_timeout_interval_1) <= 900 and int(ssh_idle_timeout_interval_2) == 0:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 487: Ensure SSH LoginGraceTime is set to one minute or less"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep logingracetime"
run_command = subprocess.check_output(command, shell=True)
ssh_login_grace_time = run_command.decode("utf-8").split()[1]

if int(ssh_login_grace_time) >= 1 and int(ssh_login_grace_time) <= 60:
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 489: Ensure SSH warning banner is configured"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep banner"
run_command = subprocess.check_output(command, shell=True)
ssh_banner = run_command.decode("utf-8")

ssh_banner_re = "banner /etc/issue.net"

if re.match(ssh_banner_re, ssh_banner):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 491: Ensure SSH PAM is enabled"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep -i usepam"
run_command = subprocess.check_output(command, shell=True)
ssh_use_pam_enabled = run_command.decode("utf-8")

ssh_use_pam_enabled_re = "usepam yes"

if re.match(ssh_use_pam_enabled_re, ssh_use_pam_enabled):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 496: Ensure SSH MaxStartups is configured"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep -i maxstartups"
run_command = subprocess.check_output(command, shell=True)
ssh_max_startups = run_command.decode("utf-8")

ssh_max_startups_re = "maxstartups 10:30:60"

if re.match(ssh_max_startups_re, ssh_max_startups):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 498: Ensure SSH MaxSessions is limited"
check_description = "-"

command = "sudo sshd -T -C user=root -C host=\"$(hostname)\" -C addr=\"$(grep $(hostname) /etc/hosts | awk '{print $1}')\" | grep -i maxsessions"
run_command = subprocess.check_output(command, shell=True)
ssh_max_sessions = run_command.decode("utf-8")

ssh_max_sessions_re = "maxsessions 10"

if re.match(ssh_max_sessions_re, ssh_max_sessions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 501: Ensure password creation requirements are configured"
check_description = "-"

command = "sudo grep -v \"^#\" /etc/security/pwquality.conf 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
password_creation_requirements = run_command.decode("utf-8")
password_creation_requirements_re = ".*minlen = 8\sdcredit = -1\sucredit = -1\slcredit = -1\sminclass = 3"

command = "sudo grep retry /etc/pam.d/password-auth 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
password_creation_requirements_2 = run_command.decode("utf-8")
password_creation_requirements_2_re = ".*retry=5\s.*"

command = "sudo grep retry /etc/pam.d/system-auth 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
password_creation_requirements_3 = run_command.decode("utf-8")
password_creation_requirements_3_re = ".*retry=5\s.*"

if re.match(password_creation_requirements_re, password_creation_requirements) and re.match(password_creation_requirements_2_re, password_creation_requirements_2) and re.match(password_creation_requirements_3_re, password_creation_requirements_3):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 504: Ensure lockout for failed password attempts is configured"
check_description = "-"

command = "sudo grep unlock /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
failed_password_lockout = run_command.decode("utf-8")

failed_password_lockout_re = ".*unlock_time=900\s.*unlock_time=900\s.*unlock_time=900\s.*unlock_time=900"

if re.match(failed_password_lockout_re, failed_password_lockout):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 509: Ensure password hashing algorithm is SHA-512"
check_description = "-"

command = "sudo grep sha512 /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
hashing_algo_sha512 = run_command.decode("utf-8")

hashing_algo_sha512_re = ".*sufficient.*sha512.*\s.*sufficient.*sha512.*"

if re.match(hashing_algo_sha512_re, hashing_algo_sha512):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 511: Ensure password reuse is limited"
check_description = "-"

command = "sudo grep pwhistory /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
limited_password_reuse = run_command.decode("utf-8")

limited_password_reuse_re = ".*remember=10\s.*remember=10"

if re.match(limited_password_reuse_re, limited_password_reuse):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 514: Ensure password expiration is 365 days or less"
check_description = "-"

command = "sudo grep -Gi \"^pass_max_days\" /etc/login.defs 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
password_expiration_90_1 = run_command.decode("utf-8")
password_expiration_90_1_re = "PASS_MAX_DAYS\s*90"

if re.match(password_expiration_90_1_re, password_expiration_90_1):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 517: Ensure minimum days between password changes is configured"
check_description = "-"

command = "sudo grep -Gi \"^pass_min_days\" /etc/login.defs 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
password_min_days = run_command.decode("utf-8")

password_min_days_re = "PASS_MIN_DAYS\s*10"

if re.match(password_min_days_re, password_min_days):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 519: Ensure password expiration warning days is 7 or more"
check_description = "-"

command = "sudo grep -Gi \"^pass_warn_age\" /etc/login.defs 2>/dev/null || true"
run_command = subprocess.check_output(command, shell=True)
password_exp_warning_days = run_command.decode("utf-8")

password_exp_warning_days_re = "PASS_WARN_AGE\s*30"

if re.match(password_exp_warning_days_re, password_exp_warning_days):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 521: Ensure inactive password lock is 30 days or less"
check_description = "-"

command = "sudo useradd -D | grep INACTIVE"
run_command = subprocess.check_output(command, shell=True)
inactive_password_lock = run_command.decode("utf-8")

inactive_password_lock_re = "INACTIVE=365"

if re.match(inactive_password_lock_re, inactive_password_lock):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 523: Ensure all users last password change date is in the past"
check_description = "-"

command = "for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo \"$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\"; done | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
pwd_change_date_past = run_command.decode("utf-8")
pwd_change_date_past_re = "0"

if re.match(pwd_change_date_past_re, pwd_change_date_past):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 524: Ensure system accounts are secured"
check_description = "-"

command = "awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\" && $1!~/^\+/ && $3<'\"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)\"' && $7!=\"'\"$(which nologin)\"'\" && $7!=\"'\"/sbin/nologin\"'\" && $7!=\"/bin/false\") {print}' /etc/passwd | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
system_accouns_are_secured_1 = run_command.decode("utf-8")

command = "awk -F: '($1!=\"root\" && $1!~/^\+/ && $3<'\"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)\"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!=\"L\" && $2!=\"LK\") {print $1}' | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
system_accouns_are_secured_2 = run_command.decode("utf-8")

system_accouns_are_secured_re = "0"

if re.match(system_accouns_are_secured_re, system_accouns_are_secured_1) and re.match(system_accouns_are_secured_re, system_accouns_are_secured_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 526: Ensure default group for the root account is GID 0"
check_description = "-"

command = "grep \"^root:\" /etc/passwd | cut -f4 -d:"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
root_account_gid_is_0 = run_command.decode("utf-8")
root_account_gid_is_0_re = "0"

if re.match(root_account_gid_is_0_re, root_account_gid_is_0):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 528: Ensure default user shell timeout is configured"
check_description = "-"

command = "sudo " + bash_scripts_location + "check_usr_shell_timeout.sh | grep PASSED | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
check_usr_shell_timeout = run_command.decode("utf-8")
check_usr_shell_timeout_re = "1"

if re.match(root_account_gid_is_0_re, root_account_gid_is_0):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 531: Ensure default user umask is configured"
check_description = "-"

command = "sudo bash " + bash_scripts_location + "check_default_user_umask.sh"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
default_user_umask_set = run_command.decode("utf-8")
default_user_umask_set_re = "Default user umask is set"

if re.match(default_user_umask_set_re, default_user_umask_set):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 538: Ensure access to the su command is restricted"
check_description = "-"

command = "grep -G \"^auth.*required\" /etc/pam.d/su"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
restricted_su_command = run_command.decode("utf-8")
restricted_su_command_re = ".*pam_wheel.so use_uid group=wheel"

if re.match(restricted_su_command_re, restricted_su_command):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 545: Ensure permissions on /etc/passwd are configured"
check_description = "-"

command = "stat /etc/passwd | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_password_permissons = run_command.decode("utf-8")
etc_password_permissons_re = ".*0644.*root.*root"

if re.match(etc_password_permissons_re, etc_password_permissons):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 547: Ensure permissions on /etc/passwd- are configured"
check_description = "-"

command = "stat /etc/passwd- | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_password_permissons_ = run_command.decode("utf-8")
etc_password_permissons_re_ = ".*0644.*root.*root"

if re.match(etc_password_permissons_re_, etc_password_permissons_):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 549: Ensure permissions on /etc/shadow are configured"
check_description = "-"

command = "stat /etc/shadow | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_shadow_permissons = run_command.decode("utf-8")
etc_shadow_permissons_re = ".*0000.*root.*root"

if re.match(etc_shadow_permissons_re, etc_shadow_permissons):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 551: Ensure permissions on /etc/shadow- are configured"
check_description = "-"

command = "stat /etc/shadow- | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_shadow_permissons_ = run_command.decode("utf-8")
etc_shadow_permissons_re_ = ".*0000.*root.*root"

if re.match(etc_shadow_permissons_re_, etc_shadow_permissons_):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 553: Ensure permissions on /etc/gshadow- are configured"
check_description = "-"

command = "stat /etc/gshadow- | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_gshadow_permissons_ = run_command.decode("utf-8")
etc_gshadow_permissons_re_ = ".*0000.*root.*root"

if re.match(etc_gshadow_permissons_re_, etc_gshadow_permissons_):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 555: Ensure permissions on /etc/gshadow are configured"
check_description = "-"

command = "stat /etc/gshadow | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_gshadow_permissons = run_command.decode("utf-8")
etc_gshadow_permissons_re = ".*0000.*root.*root"

if re.match(etc_gshadow_permissons_re, etc_gshadow_permissons):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 557: Ensure permissions on /etc/group are configured"
check_description = "-"

command = "stat /etc/group | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_group_permissons = run_command.decode("utf-8")
etc_group_permissons_re = ".*0644.*root.*root"

if re.match(etc_group_permissons_re, etc_group_permissons):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 559: Ensure permissions on /etc/group- are configured"
check_description = "-"

command = "stat /etc/group- | grep \"Access: (\""
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etc_group_permissons_ = run_command.decode("utf-8")
etc_group_permissons_re_ = ".*0644.*root.*root"

if re.match(etc_group_permissons_re_, etc_group_permissons_):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 561: Ensure no world writable files exist"
check_description = "-"

command = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_world_writable_files_exist = run_command.decode("utf-8")
no_world_writable_files_exist_re = "0"

if re.match(no_world_writable_files_exist_re, no_world_writable_files_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 563: Ensure no unowned files or directories exist"
check_description = "-"

command = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_unowned_files_exist = run_command.decode("utf-8")
no_unowned_files_exist_re = "0"

if re.match(no_unowned_files_exist_re, no_unowned_files_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 565: Ensure no ungrouped files or directories exist"
check_description = "-"

command = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_ungrouped_files_exist = run_command.decode("utf-8")
no_ungrouped_files_exist_re = "0"

if re.match(no_ungrouped_files_exist_re, no_ungrouped_files_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 567: Audit SUID executables"
check_description = "-"

command = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
audir_suid_executables = run_command.decode("utf-8")
audir_suid_executables_re = "/usr/bin/passwd\s/usr/bin/chage\s/usr/bin/gpasswd\s/usr/bin/umount\s/usr/bin/newgrp\s/usr/bin/chfn\s/usr/bin/chsh\s/usr/bin/mount\s/usr/bin/pkexec\s/usr/bin/crontab\s/usr/bin/su\s/usr/bin/at\s/usr/bin/sudo\s/usr/bin/staprun\s/usr/sbin/pam_timestamp_check\s/usr/sbin/unix_chkpwd\s/usr/sbin/usernetctl\s/usr/sbin/userhelper\s/usr/sbin/mount.nfs\s/usr/lib/polkit-1/polkit-agent-helper-1\s/usr/libexec/dbus-1/dbus-daemon-launch-helper\s/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache"

if re.match(no_ungrouped_files_exist_re, no_ungrouped_files_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 572: Ensure accounts in /etc/passwd use shadowed passwords"
check_description = "-"

command = "awk -F: '($2 != \"x\" ) { print $1 \" is not set to shadowed passwords \"}' /etc/passwd | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
accounts_in_etcpasswd_shadowed = run_command.decode("utf-8")
accounts_in_etcpasswd_shadowed_re = "0"

if re.match(accounts_in_etcpasswd_shadowed_re, accounts_in_etcpasswd_shadowed):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 574: Ensure /etc/shadow password fields are not empty"
check_description = "-"

command = "awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
etcshadow_password_fields_not_empty = run_command.decode("utf-8")
etcshadow_password_fields_not_empty_re = "0"

if re.match(etcshadow_password_fields_not_empty_re, etcshadow_password_fields_not_empty):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 576: Ensure all groups in /etc/passwd exist in /etc/group"
check_description = "-"

command = "bash " + bash_scripts_location + "check_groups_exist_in_passwd_and_group.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
all_groups_exist_in_passwd_and_group = run_command.decode("utf-8")
all_groups_exist_in_passwd_and_group_re = "0"

if re.match(all_groups_exist_in_passwd_and_group_re, all_groups_exist_in_passwd_and_group):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 578: Ensure shadow group is empty"
check_description = "-"

command = "awk -F: '($1==\"shadow\") {print $NF}' /etc/group | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
ensure_shadow_group_empty_1 = run_command.decode("utf-8")
ensure_shadow_group_empty_1_re = "0"

command = "awk -F: -v GID=\"$(awk -F: '($1==\"shadow\") {print $3}' /etc/group)\" '($4==GID) {print $1}' /etc/passwd | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
ensure_shadow_group_empty_2 = run_command.decode("utf-8")
ensure_shadow_group_empty_2_re = "0"

if re.match(ensure_shadow_group_empty_1_re, ensure_shadow_group_empty_1) and re.match(ensure_shadow_group_empty_2_re, ensure_shadow_group_empty_2):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 580: Ensure no duplicate user names exist"
check_description = "-"

command = "bash " + bash_scripts_location + "check_no_duplicate_usernames.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_duplicate_users_exist = run_command.decode("utf-8")
no_duplicate_users_exist_re = "0"

if re.match(no_duplicate_users_exist_re, no_duplicate_users_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 582: Ensure no duplicate groups exist"
check_description = "-"

command = "bash " + bash_scripts_location + "check_no_duplicate_groups.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_duplicate_groups_exist = run_command.decode("utf-8")
no_duplicate_groups_exist_re = "0"

if re.match(no_duplicate_groups_exist_re, no_duplicate_groups_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 584: Ensure no duplicate UIDs exist"
check_description = "-"

command = "bash " + bash_scripts_location + "check_no_duplicate_uids.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_duplicate_uids_exist = run_command.decode("utf-8")
no_duplicate_uids_exist_re = "0"

if re.match(no_duplicate_uids_exist_re, no_duplicate_uids_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 586: Ensure no duplicate GIDs exist"
check_description = "-"

command = "bash " + bash_scripts_location + "check_no_duplicate_gids.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_duplicate_gids_exist = run_command.decode("utf-8")
no_duplicate_gids_exist_re = "0"

if re.match(no_duplicate_gids_exist_re, no_duplicate_gids_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 588: Ensure root is the only UID 0 account"
check_description = "-"

command = "awk -F: '($3 == 0) { print $1 }' /etc/passwd"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
root_is_only_uid0 = run_command.decode("utf-8")
root_is_only_uid0_re = "root"

if re.match(root_is_only_uid0_re, root_is_only_uid0):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 589: Ensure root PATH Integrity"
check_description = "-"

command = "bash " + bash_scripts_location + "check_root_path_integrity.sh | grep -v \"root's path\" | grep -v \"is not a directory\" | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
ensure_root_path_integrity = run_command.decode("utf-8")
ensure_root_path_integrity_re = "0"

if re.match(ensure_root_path_integrity_re, ensure_root_path_integrity):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 591: Ensure all users' home directories exist"
check_description = "-"

command = "bash " + bash_scripts_location + "check_user_dirs_exist.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
user_dirs_exist = run_command.decode("utf-8")
user_dirs_exist_re = "0"

if re.match(user_dirs_exist_re, user_dirs_exist):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 593: Ensure users own their home directories"
check_description = "-"

command = "bash " + bash_scripts_location + "check_users_own_their_dirs.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
users_own_their_dirs = run_command.decode("utf-8")
users_own_their_dirs_re = "0"

if re.match(users_own_their_dirs_re, users_own_their_dirs):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 595: Ensure users' home directories permissions are 750 or more restrictive"
check_description = "-"

command = "bash " + bash_scripts_location + "check_user_home_is750or_less.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
user_home_is_750_or_less = run_command.decode("utf-8")
user_home_is_750_or_less_re = "0"

if re.match(user_home_is_750_or_less_re, user_home_is_750_or_less):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 597: Ensure users' dot files are not group or world writable"
check_description = "-"

command = "bash " + bash_scripts_location + "check_user_dot_files_permissions.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
user_dot_files_permissions = run_command.decode("utf-8")
user_dot_files_permissions_re = "0"

if re.match(user_dot_files_permissions_re, user_dot_files_permissions):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 599: Ensure no users have .forward files"
check_description = "-"

command = "bash " + bash_scripts_location + "check_no_forward_files.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_users_have_forward_files = run_command.decode("utf-8")
no_users_have_forward_files_re = "0"

if re.match(no_users_have_forward_files_re, no_users_have_forward_files):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 601: Ensure no users have .netrc files"
check_description = "-"

command = "bash " + bash_scripts_location + "check_no_netrc_files.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_users_have_netrc_files = run_command.decode("utf-8")
no_users_have_netrc_files_re = "0"

if re.match(no_users_have_netrc_files_re, no_users_have_netrc_files):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


check_name = "Page 604: Ensure no users have .rhosts files"
check_description = "-"

command = "bash " + bash_scripts_location + "check_no_rhosts_files.sh | wc -l"
run_command = subprocess.check_output(command, shell=True, stderr=DEVNULL)
no_users_have_rhosts_files = run_command.decode("utf-8")
no_users_have_rhosts_files_re = "0"

if re.match(no_users_have_rhosts_files_re, no_users_have_rhosts_files):
    task_list.append([check_name, Passed, check_description])
    total_score = total_score + lvl1_plus
else:
    task_list.append([check_name, Failed, check_description])


# Table printout #
print(tabulate(task_list, table_headers, tablefmt="fancy_grid", showindex=range(1, len(task_list) + 1) ) )
print(bloded_string_TotalScore + ": " + str(total_score) + " out of " + str(len(task_list)))

score_formula = (((total_score / (len(task_list))) * 100))
print("\033[1mScore percentage:\033[0m " + str(round(score_formula, 2)) + "%")
if score_formula > 95:
    status_string = "Green"
    status_foreground = Fore.GREEN
elif score_formula > 90:
    status_string = "Yellow"
    status_foreground = Fore.YELLOW
elif score_formula > 0:
    status_string = "Red"
    status_foreground = Fore.RED

bolded_string_SystemStatus = "\033[1m" + status_string + "\033[0m"
SystemStatus = status_foreground + bolded_string_SystemStatus + "\033[0m"
print("\033[1mSystem status:\033[0m " + SystemStatus)

print()

# print("To do:")
# print(" - Ensure GPG keys are configured. Page 76")
# print(" - Ensure package manager repositories are configured. Page 78")
# print(" - Configure and check automatic updates. Page 148.")
# print(" - Check if xorg server components are needed. Page 163.")
# print(" - Follow up on: Ensure nonessential services are removed or masked. Page 211.")
# print(" - Follow up on the: 5.3.4 Ensure SSH access is limited (Automated). Page 455.")
# print(" - Follow up on the: 5.6 Ensure root login is restricted to system console. Page 536.")
# print()


# Future:
# if __name__ == __main__:
#     main()
