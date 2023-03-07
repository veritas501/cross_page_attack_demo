qemu-system-x86_64 \
-m 512M \
-kernel bzImage \
-initrd rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet" \
-cpu qemu64,+smep,+smap \
-smp 4 \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic -monitor /dev/null --no-reboot \
-gdb tcp::1234
