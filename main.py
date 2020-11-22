import sys

from read_files import read_vulnerability_patterns, read_program
from util import fatal

def analyse(program, patterns):
    vulns = []
    
    # In the end, check if any vuln found
    if len(vulns) == 0:
        print('No vulnerabilities found!')
    else:
        print(f'Found {len(vulns)} vulnerabilities:')
        for vuln in vulns:
            print(vuln)

if __name__ == '__main__':
    if len(sys.argv) != 1 + 2:
        fatal(f'Usage: {sys.argv[0]} <program.json> <patterns.json>')

    program = read_program(sys.argv[1])
    patterns = read_vulnerability_patterns(sys.argv[2])

    analyse(program, patterns)