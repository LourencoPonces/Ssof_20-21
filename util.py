import sys
import json

debugging = False

def fatal(msg):
    print(f"[Error] {msg}")
    sys.exit(-1)


def debug(msg, level = 0):
    if debugging:
        print(f'[DBG] {"  "*level}{msg}')


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

