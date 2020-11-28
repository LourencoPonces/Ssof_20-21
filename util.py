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
    +----- expected
    |  +----- expected_xx.json
    |
    +----- outputs
    |  +----- program_xx.out.json
    |
    +----- patterns
    |  +----- pattern_yy.json
    |
    +----- programs
    |  +----- program_xx.js
    |
    +----- slices
       +----- program_xx.json

'''
# Returns output filepath that corresponds to given test path
def get_out_filepath(slice_path):
    return slice_path.parents[1] / "outputs" / f'{slice_path.stem}.out.json'

def get_expected_filepath(slice_path):
    test_number = get_test_number(slice_path.stem)
    return slice_path.parents[1] / "expected" / f'expected_{test_number}.json'

def get_test_number(slice_stem):
    return slice_stem.split("_")[1].split(".")[0]

