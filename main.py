import sys

from read_files import read_vulnerability_patterns, read_program
from util import fatal
from analyser import Analyser

if __name__ == '__main__':
    if len(sys.argv) != 1 + 2:
        fatal(f'Usage: {sys.argv[0]} <program.json> <patterns.json>')

    program = read_program(sys.argv[1])
    patterns = read_vulnerability_patterns(sys.argv[2])

    analyser = Analyser(program, patterns)
    analyser.run()
    analyser.report_vulns()
