from flow import Flow
from util import debug
from source import Source
from sink import Sink
from sanitizer import Sanitizer

'''
Represents a break in the code
'''
class Break(Exception):
    pass

'''
Represents a continue in the code
'''
class Continue(Exception):
    pass


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
    
    def backup_flows(self):
        res = {}
        for var, flow in self.variable_flows.items():
            res[var] = Flow([flow])
        return res
    
    # vf_1 - variable flows 1
    # vf_2 - variable flows 2
    # total_v - set of every key in both dictionaries
    # final_vf - resulting variable flow
    # returns if the flow has changed
    def merge_variable_flows(self, vf_1, vf_2):
        changed = False
        final_vf = {}
        total_v = set(vf_1.keys()) | set(vf_2.keys())

        for v in total_v:
            if v not in vf_1:
                final_vf[v] = vf_2[v]
                changed = True
            elif v not in vf_2:
                final_vf[v] = vf_1[v]
                changed = True
            else: 
                final_vf[v] = Flow([vf_1[v]])
                
                if final_vf[v].merge(vf_2[v]):
                    changed = True

        
        self.variable_flows =  final_vf
        return changed

    def run(self):
        self.dispatcher(self.program)
        return self.vulnerabilities

    def dispatcher(self, node):
        table = {
            'Program':                  self.analyse_program,
            'ForStatement':             self.analyse_for_statement,
            'WhileStatement':           self.analyse_while_statement,
            'DoWhileStatement':         self.analyse_do_while_statement,
            'IfStatement':              self.analyse_if_statement,
            'BlockStatement':           self.analyse_block_statement,
            'ExpressionStatement':      self.analyse_expression_statement,
            'CallExpression':           self.analyse_call_expression,
            'AssignmentExpression':     self.analyse_assignment_expression,
            'BinaryExpression':         self.analyse_binary_expression,
            'MemberExpression':         self.analyse_member_expression,
            'Identifier':               self.analyse_identifier,
            'Literal':                  self.analyse_literal,
            'BreakStatement':           self.analyse_break,
            'ContinueStatement':        self.analyse_continue,
            'UpdateExpression':         self.analyze_updateExpression
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

    def actually_analyse_while(self, while_node, do_while = False):
        test = while_node['test']
        body = while_node['body']

        changed = True
        initial_len = tmp_len = len(self.vulnerabilities)
        while_vulns = []
        
        if do_while:
            # body will always be executed at least once
            try:
                self.dispatcher(body)
            except Break:
                return
            except Continue:
                pass

        self.dispatcher(test)
        backup = self.backup_flows()
        try:
            while changed:
                try:
                    self.dispatcher(body)
                except Continue:
                    # block will stop execution. Reevaluating test
                    pass

                changed = self.merge_variable_flows(backup, self.variable_flows)
            
                # avoid reporting duplicate vulnerabilities
                new_vulns = self.vulnerabilities[tmp_len:]  # get vulns from block stmt
                for vuln in new_vulns:
                    new = True
                    for v in while_vulns:                   # check if new vuln
                        if str(v) == str(vuln):
                            new = False
                            break
                    if new:
                        while_vulns.append(vuln)
                tmp_len = len(self.vulnerabilities)
                
                # test will be executed again
                self.dispatcher(test)
                backup = self.backup_flows()

        except Break:
            # loop will exit for sure
            self.merge_variable_flows(backup, self.variable_flows)

        self.vulnerabilities = self.vulnerabilities[:initial_len] + while_vulns

    def analyse_while_statement(self, while_node):
        '''
            type: 'WhileStatement';
            test: Expression;
            body: Statement;
        '''
        self.actually_analyse_while(while_node)

    def analyse_do_while_statement(self, do_while_node):
        '''
            type: 'DoWhileStatement';
            body: Statement;
            test: Expression;
        '''
        self.actually_analyse_while(do_while_node, do_while = True)

    def analyse_for_statement(self, for_node):
        '''
            type: 'ForStatement';
            init: Expression | VariableDeclaration | null;
            test: Expression | null;
            body: Statement;
            update: Expression | null;
        '''

        init = for_node['init']
        test = for_node['test']
        update = for_node['update']
        body = for_node['body']

        self.dispatcher(init)

        changed = True
        initial_len = tmp_len = len(self.vulnerabilities)
        for_vulns = []

        backup = self.backup_flows()
        try:
            while changed:
                try:
                    self.dispatcher(body)
                except Continue:
                    # block will stop execution. Reevaluating test
                    pass

                self.dispatcher(update)

                changed = self.merge_variable_flows(backup, self.variable_flows)
            
                # avoid reporting duplicate vulnerabilities
                new_vulns = self.vulnerabilities[tmp_len:]  # get vulns from block stmt
                for vuln in new_vulns:
                    new = True
                    for v in for_vulns:                   # check if new vuln
                        if str(v) == str(vuln):
                            new = False
                            break
                    if new:
                        for_vulns.append(vuln)
                tmp_len = len(self.vulnerabilities)
                
                # test will be executed again
                self.dispatcher(test)
                backup = self.backup_flows()

        except Break:
            # loop will exit for sure
            self.merge_variable_flows(backup, self.variable_flows)

        self.vulnerabilities = self.vulnerabilities[:initial_len] + for_vulns

    def analyse_break(self, break_node):
        '''
        type: 'BreakStatement';
        label: Identifier | null;
        '''
        raise Break()
    
    def analyse_continue(self, continue_node):
        '''
        type: 'ContinueStatement';
        label: Identifier | null;
        '''
        raise Continue()

    def analyse_if_statement(self, if_node):
        '''
            type: 'IfStatement';
            test: Expression;
            consequent: Statement;
            alternate?: Statement;
        '''
        test = if_node['test']
        consequent = if_node['consequent']
        
        recvd_breaks = 0
        recvd_continue = 0  

        self.dispatcher(test)

        # flow at if arrival
        try:
            previous_flow = self.backup_flows()
            self.dispatcher(consequent)
        except Break:
            recvd_breaks += 1
        except Continue:
            recvd_continue += 1
        
        # flow resulting from the `then` statement
        consequent_flow = self.backup_flows()

        if if_node['alternate'] != None:
            # restore arrival flow
            self.variable_flows = previous_flow
            
            try:
                self.dispatcher(if_node['alternate'])
            except Break:
                recvd_breaks += 1
            except Continue:
                recvd_continue += 1

            self.merge_variable_flows(self.variable_flows, consequent_flow)
        else:
            self.merge_variable_flows(previous_flow, consequent_flow)
        
        # if { break } else { break } will always break!
        if recvd_breaks == 2:
            raise Break()
        
        # if { continue } else { continue } will always continue!
        # if { continue } else { break } will at least continue
        if recvd_continue == 2 or (recvd_breaks == 1 and recvd_continue == 1):
            raise Continue()

    def analyse_block_statement(self, block_node):
        '''
            type: 'BlockStatement';
            body: StatementListItem[];
        '''
        statements = block_node['body']

        statement_flows = []
        for statement in statements:
            self.dispatcher(statement)

    def analyse_expression_statement(self, expression_node):
        '''
            type: 'ExpressionStatement';
            expression: Expression;
            directive?: string;
        '''
        self.dispatcher(expression_node['expression'])
        expression_node['flow'] = Flow([expression_node['expression']['flow']])

    def analyze_updateExpression(self, update_expression_node):
        '''
        type: 'UpdateExpression';
        operator: '++' | '--';
        argument: Expression;
        prefix: boolean;
        '''
        self.dispatcher(update_expression_node['argument'])
        update_expression_node['flow'] = update_expression_node['argument']['flow']
        return

    def analyse_call_expression(self, call_node):
        '''
            type: 'CallExpression';
            callee: Expression | Import;
            arguments: ArgumentListElement[];
        '''
        callee = call_node['callee']
        arguments = call_node['arguments']
        self.dispatcher(callee)
        callee_flow = callee['flow']
        
        argument_flows = []
        for argument in arguments:
            self.dispatcher(argument)
            argument_flows.append(argument['flow'])
        
        args_flow = Flow(argument_flows)
        args_flow.remove_sinks()

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
        left_flow.remove_sanitizers()
        right_flow.remove_sinks()
        
        resulting_flow = Flow([right_flow, left_flow])
        assignment_node['flow'] = Flow([right_flow])
        

        # Variable from left gets flow from right
        # NOTE: left node doesn't need to get the flow from right
        # NOTE: we want to keep track of left sinks
        self.variable_flows[left['full_name']] = Flow([resulting_flow])

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

