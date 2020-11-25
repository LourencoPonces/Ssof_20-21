import os
import sys
import json
from util import fatal

def read_program (program_file_path):
    try:
        with open(program_file_path, 'r') as json_file:
            return json.load(json_file)
    except IOError:
        fatal(f'Program file: {program_file_path} does not exist')

def read_vulnerability_patterns (patterns_file_path):
    patterns = []
    try:
        with open(patterns_file_path, 'r') as json_file:
            return json.load(json_file)
    except IOError:
        fatal(f'Patterns file: {patterns_file_path} does not exist')    