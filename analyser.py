from flow import Flow
from util import debug
from source import Source

class Analyser:
    def __init__(self, program, patterns):
        self.program = program              # the program to analyse        JSON
        self.patterns = patterns            # the patterns to consider      [Pattern, ...]
        self.vulnerabilities = []           # register vulnerabilities      [Vulnerability, ...]
        self.variable_flows = {}                 # found variables               {Variable : Taint/Source?, ...}
        self.depth = 0

    def is_source(self, potential):
        res_patts = []
        for patt in self.patterns:
            if patt.detect_source(potential):
                res_patts.append(patt)
        return res_patts

    def is_sanitizer(self, potential):
        res_patts = []
        for patt in self.patterns:
            if patt.detect_sanitizer(potential):
                res_patts.append(patt)
        return res_patts

    def is_sink(self, potential):
        res_patts = []
        for patt in self.patterns:
            if patt.detect_sink(potential):
                res_patts.append(patt)
        return res_patts

    def run(self):
        self.dispatcher(self.program)

    def dispatcher(self, node):
        table = {
            'Program':                  self.analyse_program,
            'ExpressionStatement':      self.analyse_expression,
            'CallExpression':           self.analyse_call,
            'AssignmentExpression':     self.analyse_assignment,
            'BinaryExpression':         self.analyse_binary_expression,
            'MemberExpression':         self.analyse_member_expression,
            'Identifier':               self.analyse_identifier,
            'Literal':                  self.analyse_literal
        }

        node_type = node['type']
        if node_type in table:
            self.depth = self.depth + 1
            debug(f'Visiting {node_type}', self.depth)
            table[node_type](node)
            self.depth -= 1
        else:
            print(f'Node {node_type} not recognized')

    def analyse_program(self, program_node):
        for instruction in program_node['body']:
            # print(instruction)
            self.dispatcher(instruction)

    def analyse_expression(self, expression_node):
        self.dispatcher(expression_node['expression'])

    def analyse_call(self, call_node):
        '''
            type: 'CallExpression';
            callee: Expression | Import;
            arguments: ArgumentListElement[];
        '''
        callee = call_node['callee']
        arguments = call_node['arguments']
        self.dispatcher(callee)
        
        argument_flows = []
        for argument in arguments:
            self.dispatcher(argument)
            argument_flows.append(argument['flow'])

        # Functions pass the flow from their arguments
        arg_flow = Flow(argument_flows)
        call_node['flow'] = arg_flow

        self.vulnerabilities += arg_flow.check_sink(callee['full_name'])
        
    def analyse_assignment(self, assignment_node):
        '''
            type: 'AssigmentExpression';
            operator: '=' | '*=' | '**=' | '/=' | '%=' | '+=' | '-=' |'<<=' | '>>=' | '>>>=' | '&=' | '^=' | '|=';
            left: Identifier;
            right: Identifier;
        '''
        left = assignment_node['left']
        right = assignment_node['right']
        operator = assignment_node['operator']
        
        self.dispatcher(left)
        self.dispatcher(right)
        
        debug(f"AssignmentExpression: {left['full_name']} {operator} {right['full_name']}", self.depth)

        # Assignment node gets flow from right
        flow = Flow([right['flow']])
        assignment_node['flow'] = flow
        
        # Variable from left gets flow from right
        # NOTE: left node doesn't need to get the flow from right
        self.variable_flows[left['full_name']] = flow
        
        # Check if left is sink
        self.vulnerabilities += flow.check_sink(left['full_name'])
        
    def analyse_binary_expression(self, binary_node):
        '''
            type: 'BinaryExpression';
            operator: 'instanceof' | 'in' | '+' | '-' | '*' | '/' | '%' | '**' | '|' | '^' | '&' | '==' | '!=' | '===' | '!==' | '<' | '>' | '<=' | '<<' | '>>' | '>>>';
            left: Expression;
            right: Expression;
        '''
        left = binary_node['left']
        right = binary_node['right']
        operator = binary_node['operator']
        print(f"BinaryExpression: {left['full_name']} {operator} {right['full_name']}")
        self.dispatcher(left)
        self.dispatcher(right)

        binary_node['flow'] = Flow([left['flow'], right['flow']])
        binary_node['full_name'] = f"{left['full_name']} {operator} {right['full_name']}"

    def analyse_member_expression(self, member_node):
        '''
            type: 'MemberExpression';
            computed: boolean;
            object: Expression;
            property: Expression;
        '''
        full_name = ''
        object = member_node['object']
        property = member_node['property']
        self.dispatcher(object)
        self.dispatcher(property)

        if member_node['computed']:
            print(f"Member Expression: {object['full_name']}[{property['full_name']}]")
            member_node['full_name'] = f"{object['full_name']}[{property['full_name']}]"    # a[1]
            full_name = member_node['full_name']
        else:
            print(f"MemberExpression: {object['full_name']}.{property['full_name']}")
            member_node['full_name'] = f"{object['full_name']}.{property['full_name']}"     # a.b
            full_name = member_node['full_name']
        
        if full_name not in self.variable_flows:
            patts = self.is_source(full_name)
            if len(patts) != 0:
                member_node['flow'] = Flow([Source(identifier = full_name, patterns = patts)])
            else:
                identifier_node['flow'] = Flow([])
        else:
            member_node['flow'] = self.variable_flows[full_name]

    def analyse_identifier(self, identifier_node):
        '''
            type: 'Identifier';
            name: string;
        '''
        name = identifier_node['name']
        debug(f'Identifier: "{name}"', self.depth)

        if name not in self.variable_flows:
            patts = self.is_source(name)
            if len(patts) != 0:
                identifier_node['flow'] = Flow([Source(identifier = name, patterns = patts)])
            else:
                identifier_node['flow'] = Flow([])
            # Has to account for it being a function call
            # self.variable_flows[name] = identifier_node['flow']
        else:
            identifier_node['flow'] = self.variable_flows[name]

        # used above in recursion to find the full name (e.g. MemberExpression)
        identifier_node['full_name'] = name

    def analyse_literal(self, literal_node):
        '''
            type: 'Literal';
            value: boolean | number | string | RegExp | null;
            raw: string;
        '''
        value = literal_node["value"]
        print(f'Literal: {value}')
        literal_node['flow'] = Flow([])

        literal_node['full_name'] = literal_node['raw']

    def report_vulns(self):
        if len(self.vulnerabilities) == 0:
            print('No vulnerabilities found!')
        else:
            print(f'Found vulnerabilities: {len(self.vulnerabilities)}')
            for vuln in self.vulnerabilities:
                print(vuln)
