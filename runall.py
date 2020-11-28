import sys
from pathlib import Path

from main import go
from util import *


PASSED = 0
FAILED = 1
NO_OUT = 2
NO_EXP = 3



def verify_output(program_path):
    out_path = get_out_filepath(program_path)
    exp_path = get_expected_filepath(program_path)

    if not out_path.exists():
        return NO_OUT
    
    if not exp_path.exists():
        return NO_EXP

    out = read_json(out_path)
    exp = read_json(exp_path)
    return PASSED if sort_dict(out) == sort_dict(exp) else FAILED

if __name__ == '__main__':
    if len(sys.argv) != 1 + 2:
        fatal(f'Usage: {sys.argv[0]} <program_directory> <patterns.json>')

    slices_path = Path(sys.argv[1])#.resolve()
    pattern_path = Path(sys.argv[2])#.resolve()

    if not (slices_path.exists() and slices_path.is_dir()):
        fatal(f'given program directory does not exist')

    if not (pattern_path.exists() and pattern_path.is_file()):
        fatal(f'given pattern file does not exist')

    slices = [f for f in slices_path.iterdir() if f.suffix == '.json' or len(f.suffixes) != 1]
    slices.sort()
    passed = 0
    for slice_path in slices:

        out_path = get_out_filepath(slice_path)
        if out_path.exists():
            out_path.unlink()

        go(slice_path, pattern_path)

        result = verify_output(slice_path)
        if result == PASSED:
            passed += 1
            print(f"{slice_path} PASSED")
        elif result == FAILED:
            print(f"{slice_path} FAILED")
        elif result == NO_OUT:
            print(f"{slice_path} No output file")
        elif result == NO_EXP:
            print(f"{slice_path} No exp file")

    print(f"Passed {passed}/{len(slices)} ({100*passed/len(slices)}%)")