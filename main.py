import sys

from util import fatal
from pattern import Pattern
from analyser import Analyser
from read_files import read_vulnerability_patterns, read_program

if __name__ == '__main__':
    if len(sys.argv) != 1 + 2:
        fatal(f'Usage: {sys.argv[0]} <program.json> <patterns.json>')

    program = read_program(sys.argv[1])
    patterns_json = read_vulnerability_patterns(sys.argv[2])
    patterns = []

    for patt in patterns_json:
        patterns.append(Pattern(patt))

    analyser = Analyser(program, patterns)
    vulnerabilities = analyser.run()

    if len(vulnerabilities) == 0:
        print('No vulnerabilities found!')
    else:
        print(f'Found vulnerabilities: {len(vulnerabilities)}')
        for vuln in vulnerabilities:
            print(vuln)
