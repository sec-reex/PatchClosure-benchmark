#!/usr/bin/env python3
"""Plant RUN_FLAG into /flag.txt and /app/secret.h5 (float32, 4-byte aligned)."""
import os

import h5py
import numpy as np

f = os.environ["PCB_FLAG"].encode()
n = max(32, ((len(f) + 3) // 4) * 4)
d = f + bytes(n - len(f))
open("/flag.txt", "wb").write(d)
with h5py.File("/app/secret.h5", "w") as h:
    h.create_dataset("data", data=np.frombuffer(d, dtype="float32").reshape(n // 4, 1))
