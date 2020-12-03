import sys
import json
from pathlib import Path

from util import *
from pattern import Pattern
from analyser import Analyser

def go(program_path, pattern_path):
    if not (program_path.exists() and program_path.is_file()):
        fatal(f'given program file does not exist')

    if not (pattern_path.exists() and pattern_path.is_file()):
        fatal(f'given pattern file does not exist')

    output_path = get_out_filepath(program_path.parents[0])

    program = read_json(program_path)
    patterns_json = read_json(pattern_path)
    patterns = []

    for patt in patterns_json:
        patterns.append(Pattern(patt))

    analyser = Analyser(program, patterns)
    vulnerabilities = analyser.run()

    json_vulns = json.dumps([vuln.to_dict() for vuln in vulnerabilities], indent=2)
    debug(json_vulns)
    output_path.write_text(json_vulns)

    debug(f'Found vulnerabilities: {len(vulnerabilities)}')
    debug(vulnerabilities)

    # may be used by tester program
    return vulnerabilities

if __name__ == '__main__':
    if len(sys.argv) != 1 + 2:
        fatal(f'Usage: {sys.argv[0]} <program.json> <patterns.json>')

    program_path = Path(sys.argv[1]).resolve()
    pattern_path = Path(sys.argv[2]).resolve()

    go(program_path, pattern_path)
