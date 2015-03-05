__author__ = 'crunch'

import subprocess
import re

try:
    chrome_pids = subprocess.check_output(['ps', 'hf', '-opid,cmd', '-Cchrome'])
except subprocess.CalledProcessError:
    pass

regexp_line = '[0-9]+ /.*\n'
pattern = re.compile(regexp_line, re.IGNORECASE)
results = re.findall(pattern, chrome_pids)
pid = 0

for line in results:
    if not 'zygote' in line:
        pid = re.search('[0-9]+', line).group()

if pid == 0:
    print(pid)

# subprocess.call('pkexec' )
subprocess.call('echo "password" | sudo -S ../tracedump/tracedump ' + pid, shell=True)
