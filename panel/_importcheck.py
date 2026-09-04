import sys
sys.path.insert(0, r"C:\Users\Admin\Documents\GitHub\ss-zapret2\panel")
import server
st = server._tspu_intel.status()
print("SERVER_IMPORT_OK mode=" + st["mode"] + " path=" + st["log_path"])
print("endpoints_present=" + str(hasattr(server.Handler, "do_GET")))