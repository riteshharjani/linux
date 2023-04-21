import pexpect
import sys
import requests
from tqdm import tqdm
import re

#url = 'https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img'
#local_filename = 'focal-server-cloudimg-amd64.img'
#
#response = requests.get(url, stream=True)
#response.raise_for_status()  # Raise an exception if the download failed
#
#total_size = int(response.headers.get('content-length', 0))
#chunk_size = 8192
#
#with open(local_filename, 'wb') as f:
#    for chunk in tqdm(response.iter_content(chunk_size=chunk_size), total=total_size // chunk_size, unit='KB'):
#        f.write(chunk)

# Change this to the path of your downloaded Ubuntu cloud image
cloud_image_path = './jammy-server-cloudimg-amd64.img'

#                 -device virtio-net,netdev=vmnic \
#                 -netdev user,id=vmnic,hostfwd=tcp::12125-:22 \
# Create a pexpect object to run the QEMU command
qemu_command = f'''qemu-system-x86_64 \
                 -enable-kvm
                 -smp 2 \
                 -nographic \
                 -m 2048 \
                 -kernel arch/x86/boot/bzImage \
                 -drive file={cloud_image_path},format=qcow2 \
                 -drive file=user-data.img,format=raw \
                 -monitor telnet:127.0.0.1:55555,server,nowait -serial mon:stdio \
                 -serial telnet:127.0.0.1:1234,server,nowait \
                 -fsdev local,id=shared_test_dev,path=/root,security_model=none \
                 -device virtio-9p-pci,fsdev=shared_test_dev,mount_tag=host_shared \
	         -net nic,model=virtio -net user,hostfwd=tcp:127.0.0.1:2001-:22 \
                 -append "console=ttyS0,115200n8 root=/dev/sda1'''
child = pexpect.spawn(qemu_command, timeout=3000, encoding="utf-8")
child.logfile = sys.stdout

# Log in to the system
child.expect('ubuntu login:')
child.sendline('qemu')
child.expect('Password:')
child.sendline('123')
child.expect('qemu@ubuntu.*$')

child.sendline('sudo su')
child.expect('root@ubuntu.*#')

child.sendline('cd /root/')
child.expect('root@ubuntu.*#')

# Execute the commands
commands = ['ls', 'df -h', 'lsblk', 'mount', 'uname -a']
for command in commands:
    child.sendline(command)
    child.expect('root@ubuntu.*')
    #print(f'Output of \'{command}\':')
    #print(child.before)

child.sendline("sudo apt -y remove needrestart")
child.expect('root@ubuntu.*')
child.sendline("apt-get update")
child.expect('root@ubuntu.*')

child.sendline("apt-get install -y python3 python3-pip")
child.expect('root@ubuntu.*')

child.sendline("pip3 install avocado-framework avocado-framework-plugin-varianter-yaml-to-mux")
child.expect('root@ubuntu.*')

child.sendline("parted /dev/sda resizepart 1 100% && sudo resize2fs /dev/sda1")
child.expect('root@ubuntu.*#')


child.sendline("df -h")
child.expect('root@ubuntu.*#')

child.sendline("rm -rf avocado-misc-tests")
child.expect('root@ubuntu.*#')


child.sendline("mkdir host_shared")
child.expect('root@ubuntu.*#')

child.sendline("mount -t 9p -o trans=virtio host_shared host_shared -oversion=9p2000.L")
child.expect('root@ubuntu.*#')

child.sendline("git clone https://github.com/riteshharjani/avocado-misc-tests.git")
child.expect('root@ubuntu.*#')

child.sendline("cd avocado-misc-tests")
child.expect('root@ubuntu.*#')

child.sendline("bash -c 'echo 9 > /proc/sys/kernel/printk'")
child.expect('root@ubuntu.*#')

child.sendline("avocado run fs/xfstests.py -m fs/xfstests.py.data/tests.yaml --max-parallel-tasks 1")
child.expect('root@ubuntu.*#')

print(child.before)

match = re.search(r"JOB LOG\s*:\s*(.+)", child.before)
if match:
    job_log_path = match.group(1)
    print("Job log path:", job_log_path)
else:
    job_log_path = ""
    print("Job log path not found")

child.sendline(f"cat {job_log_path}")
child.expect('root@ubuntu.*#')


# Exit QEMU
child.sendline('sudo poweroff')
child.expect(pexpect.EOF)

