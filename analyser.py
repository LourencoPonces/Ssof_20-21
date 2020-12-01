from flow import Flow
from util import debug
from source import Source
from sink import Sink
from sanitizer import Sanitizer

class Analyser:
    def __init__(self, program, patterns):
        self.program = program              # the program to analyse        JSON
        self.patterns = patterns            # the patterns to consider      [Pattern, ...]
        self.vulnerabilities = []           # register vulnerabilities      [Vulnerability, ...]
        self.variable_flows = {}            # found variables               {Variable : Taint/Source?, ...}
        self.depth = 0

    def is_source(self, potential):
        res_patts = []
        for patt in self.patterns:
            if patt.detect_source(potential):
                res_patts.append(patt)
        return res_patts
    
    def is_sink(self, potential):
        res_patts = []
        for patt in self.patterns:
            if patt.detect_sink(potential):
                res_patts.append(patt)
        return res_patts
    
    def is_sanitizer(self, potential):
        res_patts = []
        for patt in self.patterns:
            if patt.detect_sanitizer(potential):
                res_patts.append(patt)
        return res_patts


    def get_identifier_flow(self, identifier):
        if identifier in self.variable_flows:
            # get existing flow
            flow = self.variable_flows[identifier]
        else:
            # new variable: check if source/sink/sanitizer
            flows = []
            flows.append(Source(identifier, self.is_source(identifier)))
            flows.append(Sink(identifier, self.is_sink(identifier)))
            flows.append(Sanitizer(identifier, self.is_sanitizer(identifier)))
            flow = Flow(flows)

        return flow

    def run(self):
        self.dispatcher(self.program)
        return self.vulnerabilities

    def dispatcher(self, node):
        table = {
            'Program':                  self.analyse_program,
            'WhileStatement':           self.analyse_while_statement,
            'IfStatement':              self.analyse_if_statement,
            'BlockStatement':           self.analyse_block_statement,
            'ExpressionStatement':      self.analyse_expression_statement,
            'CallExpression':           self.analyse_call_expression,
            'AssignmentExpression':     self.analyse_assignment_expression,
            'BinaryExpression':         self.analyse_binary_expression,
            'MemberExpression':         self.analyse_member_expression,
            'Identifier':               self.analyse_identifier,
            'Literal':                  self.analyse_literal
        }

        node_type = node['type']
        if node_type in table:
            debug(f'Visiting {node_type}', self.depth)
            self.depth = self.depth + 1
            table[node_type](node)
            self.depth -= 1
        else:
            print(f'Node {node_type} not recognized')

    def analyse_program(self, program_node):
        for instruction in program_node['body']:
            self.dispatcher(instruction)

    def analyse_while_statement(self, while_node):
        '''
            type: 'WhileStatement';
            test: Expression;
            body: Statement;
        '''
        return

    def analyse_if_statement(self, if_node):
        '''
            type: 'IfStatement';
            test: Expression;
            consequent: Statement;
            alternate?: Statement;
        '''
        test = if_node['test']
        consequent = if_node['consequent']
        alternate = if_node['alternate']
        self.dispatcher(test)
        self.dispatcher(consequent)
        self.dispatcher(alternate)
        if_full_name = '\n' + '  ' * (self.depth + 3) + f"if({test['full_name']}) {consequent['full_name']}"
        if alternate != 'null':
            if_full_name += '\n' + '  ' * (self.depth + 3) + f"else {alternate['full_name']}"

        debug(f"IfStatement: {if_full_name}", self.depth)

        if_node['full_name'] = if_full_name

    def analyse_block_statement(self, block_node):
        '''
            type: 'BlockStatement';
            body: StatementListItem[];
        '''
        statements = block_node['body']

        statement_flows = []
        block_full_name = '\n' + '  ' * (self.depth + 3) + '{\n'
        for statement in statements:
            self.dispatcher(statement)
            statement_flows.append(statement['flow'])
            block_full_name += '  ' * (self.depth + 3) + '    ' + statement['full_name'] + '\n'
        block_full_name += '  ' * (self.depth + 3) + '}'

        debug(f"BlockStatement: {block_full_name}", self.depth)

        block_node['flow'] = Flow(statement_flows)
        block_node['full_name'] = block_full_name

    def analyse_expression_statement(self, expression_node):
        '''
            type: 'ExpressionStatement';
            expression: Expression;
            directive?: string;
        '''
        self.dispatcher(expression_node['expression'])
        expression_node['flow'] = Flow([expression_node['expression']['flow']])

    def analyse_call_expression(self, call_node):
        '''
            type: 'CallExpression';
            callee: Expression | Import;
            arguments: ArgumentListElement[];
        '''
        callee = call_node['callee']
        arguments = call_node['arguments']
        self.dispatcher(callee)
        
        argument_flows = []
        arguments_full_name = ''
        for argument in arguments:
            self.dispatcher(argument)
            argument_flows.append(argument['flow'])
        

        callee_flow = callee['flow']
        args_flow = Flow(argument_flows)
        # args_flow.remove_sanitizers()
        # args_flow.remove_sinks()

        call_flow = Flow([callee_flow, args_flow])
        call_node['flow'] = call_flow

        self.vulnerabilities += call_flow.check_vulns()
        
    def analyse_assignment_expression(self, assignment_node):
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

        # Assignment node gets flow from right
        right_flow = right['flow']
        left_flow  =  left['flow']

        # we don't want to account for left sources: they will be overwritten
        left_flow.remove_sources()

        resulting_flow = Flow([right_flow, left_flow])
        assignment_node['flow'] = Flow([right_flow])
        
        # Variable from left gets flow from right
        # NOTE: left node doesn't need to get the flow from right
        self.variable_flows[left['full_name']] = right_flow

        # Check if left is sink
        self.vulnerabilities += resulting_flow.check_vulns()
        
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
            full_name = f"{object['full_name']}[{property['full_name']}]"    # a[1]
        else:
            full_name = f"{object['full_name']}.{property['full_name']}"     # a.b

        member_node['full_name'] = full_name
        debug(f"Member Expression: {full_name}", self.depth)
        member_node['flow'] = self.get_identifier_flow(full_name)

    def analyse_identifier(self, identifier_node):
        '''
            type: 'Identifier';
            name: string;
        '''
        name = identifier_node['name']
        debug(f'Identifier: "{name}"', self.depth)

        # used above in recursion to find the full name (e.g. MemberExpression)
        identifier_node['full_name'] = name
        identifier_node['flow'] = self.get_identifier_flow(name)

    def analyse_literal(self, literal_node):
        '''
            type: 'Literal';
            value: boolean | number | string | RegExp | null;
            raw: string;
        '''
        value = literal_node["value"]
        debug(f'Literal: {value}', self.depth)
        literal_node['flow'] = Flow([])

        literal_node['full_name'] = literal_node['raw']

