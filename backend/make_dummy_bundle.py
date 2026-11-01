import os, struct

payload = os.urandom(1000)
data = os.urandom(768) + os.urandom(2420) + os.urandom(16) + struct.pack("<I", len(payload)) + payload

open("dummy_bundle.bin", "wb").write(data)
print(len(data), "bytes")