#!/usr/bin/env bash -eux

mkdir /etc/chef
# mv ${staging_directory}/encrypted_data_bag_secret /etc/chef/encrypted_data_bag_secret
# chmod 600 /etc/chef/encrypted_data_bag_secret
# passwd -d chef
# passwd -l chef
chage -M 99999 chef

# ensure root is diabled
passwd -d root
passwd -l root

# ensure the root is never allowed to login to a system directly over a network
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config
cat /etc/ssh/sshd_config
# disable X11Forwarding in ssh
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config

# disable X11Forwarding in ssh
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config

# set ClientAliveInterval to 15min in ssh
echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config

# ensure the ssh idle timeout occurs precisely when the ClientAliveCountMax is set in ssh
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

# disable root login in ssh
sed -i 's/#PermitRootLogin no/PermitRootLogin no/g' /etc/ssh/sshd_config

# allow pubkey authentication
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config

cat /etc/ssh/sshd_config

# harden sysctl parameters
# echo "fs.protected_symlinks = 1" >> /etc/sysctl.conf
# echo "fs.protected_hardlinks = 1" >> /etc/sysctl.conf
# echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
# echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
# echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
# echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
# echo "kernel.unprivileged_userns_clone = 0" >> /etc/sysctl.conf
# echo "vm.swappiness=1" >> /etc/sysctl.conf
# echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
# /sbin/sysctl -p

# harden grub parameters
echo 'GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"' >> /etc/default/grub
echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/default/grub
echo 'audit=1' >> /etc/default/grub
su -c 'update-grub'

# disable unprivileged BPF
echo 1 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled

apt-get install ufw -y
ufw enable
ufw allow ssh

# harden umask settings:
su -c "cat ${staging_directory}/files/login_defs > /etc/login.defs"

# assure ntpd is enabled / started
systemctl enable ntp
systemctl start ntp

# assure rsyslog is enabled
sed -i 's/weekly/daily/g' /etc/logrotate.conf
systemctl enable rsyslog

# assure auditd is enabled
systemctl enable auditd

# assure acct is enabled
systemctl enable acct

# add modprode blacklist
su -c "cat ${staging_directory}/files/hardening.conf > /etc/modprobe.d/hardening.conf"
su -c "cat ${staging_directory}/files/hardening-wireless.conf > /etc/modprobe.d/hardening-wireless.conf"
su -c "chmod 644 /etc/modprobe.d/hardening.conf"
su -c "chmod 644 /etc/modprobe.d/hardening-wireless.conf"

echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
cat /etc/fstab
