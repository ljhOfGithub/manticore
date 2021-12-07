#!/usr/bin/env python3

import os
import sys

# Checks whether files listed via stdin actually exist检查通过stdin列出的文件是否实际存在
for f in sys.stdin.readlines():
    line = f.strip()
    if line.endswith(".py") and os.path.exists(line):
        print(line)
