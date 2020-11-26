import sys

debugging = True

def fatal(msg):
    print(f"[Error] {msg}")
    sys.exit(-1)


def debug(msg, level = 0):
    if debugging:
        print(f'[DBG] {"  "*level}{msg}')
