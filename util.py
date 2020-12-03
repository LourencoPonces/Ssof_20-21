import sys
import json

PASSED = "OK"
FAILED = "NOK"
ERROR = "ERROR"
NO_OUT = "NO OUT"
NO_EXP = "NO EXP"

DEFAULT = '\033[0m'
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'


debugging = True
colors = True


def init(debug = True, color = True):
    global debugging
    global colors

    debugging = debug
    colors = color


def fatal(msg):
    print(f"[Error] {msg}")
    sys.exit(-1)


def debug(msg, level = 0):
    if debugging:
        print(f'[DBG] {"  "*level}{msg}')


def color_result(result):
    result_colors = {
        PASSED: OKGREEN,
        FAILED: FAIL,
        ERROR: FAIL,
        NO_OUT: WARNING,
        NO_EXP: WARNING
    }
    if colors and result in result_colors:
        return BOLD + result_colors[result] + result + DEFAULT
    return result


# Sort json objects, to compare them correctly
# Source: https://stackoverflow.com/questions/25851183/how-to-compare-two-json-objects-with-the-same-elements-in-a-different-order-equa
def sort_dict(obj):
    if isinstance(obj, dict):
        return sorted((k, sort_dict(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj



def read_json(filepath):
    try:
        with open(filepath, 'r') as json_file:
            return json.load(json_file)
    except IOError:
        fatal(f'File: {filepath} does not exist')


'''
Test Directory Structure:
    / 
    +----- programs
    |  +----- test_name
    |  |   +----- expected.json
    |  |   +----- test_name.json
    |  |   +----- test_name.js
    |  |   +----- test_name.out.json
    | ...
    +----- patterns
    |  +----- pattern_yy.json
    | ...
     
'''
# Returns output filepath that corresponds to given test path
def get_out_filepath(test_dir):
    return test_dir / f'{test_dir.stem}.out.json'

def get_exp_filepath(test_dir):
    return test_dir / "expected.json"

def get_ast_filepath(test_dir):
    return test_dir / f'{test_dir.stem}.json'

