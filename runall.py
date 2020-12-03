import sys
from pathlib import Path

from main import go
from util import *
from read_files import read_json


def report_result(test_name, result):
    cols = os.get_terminal_size(1).columns
    test_name = test_dir.stem
    num_dash = cols - len(result) - len(test_name) - 7
    print(f'[ {test_name} {"-"*num_dash}> {color_result(result)} ]')

def verify_output(test_dir):
    out_path = get_out_filepath(test_dir)
    exp_path = get_exp_filepath(test_dir)

    if not out_path.exists():
        return NO_OUT
    
    if not exp_path.exists():
        return NO_EXP

    out = read_json(out_path)
    exp = read_json(exp_path)
    return PASSED if sort_dict(out) == sort_dict(exp) else FAILED

if __name__ == '__main__':
    init(debug = False, color = True)

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
    for slice_path in slices:

        if out_path.exists():
            out_path.unlink()

        try:
            go(ast_path, pattern_path)
            result = verify_output(test_dir)
        except:
            result = ERROR

        report_result(test_dir, result)

        result = verify_output(slice_path)
        if result == PASSED:
            print("PASSED")
        elif result == FAILED:
            print("FAILED")
        elif result == NO_OUT:
            print("No output file")
        elif result == NO_EXP:
            print("No exp file")
