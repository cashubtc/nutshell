import subprocess
try:
    subprocess.check_call(["pytest", "tests/test_mint_watchdog.py"])
except Exception as e:
    print(e)
