import os
import time

from opsim.firmware import firmware
firmware.build()
os.utime(firmware.path, (time.time(),) * 2)
