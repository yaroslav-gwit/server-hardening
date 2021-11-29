#!/usr/bin/env bash

### CSI ###
# tst1=""
# tst2=""
# output=""

# efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
# gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')

# if [ -f "$efidir"/grub.cfg ]; then grubdir="$efidir" && grubfile="$efidir/grub.cfg"
# elif [ -f "$gbdir"/grub.cfg ]; then grubdir="$gbdir" && grubfile="$gbdir/grub.cfg"
# fi

# userfile="$grubdir/user.cfg"

# [ -f "$userfile" ] && grep -Pq '^\h*GRUB2_PASSWORD\h*=\h*.+$' "$userfile" && output="\n PASSED: bootloader password set in \"$userfile\"\n\n"

# if [ -z "$output" ] && [ -f "$grubfile" ]; then grep -Piq '^\h*set\h+superusers\h*=\h*"?[^"\n\r]+"?(\h+.*)?$' "$grubfile" && tst1=pass grep -Piq '^\h*password\h+\H+\h+.+$' "$grubfile" && tst2=pass [ "$tst1" = pass ] && [ "$tst2" = pass ] && output="\n\n*** PASSED: bootloader password set in \"$grubfile\" ***\n\n" fi [ -n "$output" ] && echo -e "$output" || echo -e "\n\n *** FAILED: bootloader password is not set ***\n\n"
# fi

### MY_OWN ###
FILE_1 = /boot/efi/EFI/centos/user.cfg

if [-f /boot/efi/EFI/centos/user.cfg]; then cat $FILE_1 | grep -ci password || true; fi