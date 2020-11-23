from taint import Taint

class Analyser:
    def __init__(self, program, patterns):
        self.program = program              # the program to analyse
        self.patterns = patterns            # the patterns to consider
        self.vulnerabilities = []           # register vulnerabilities
        self.identifiers = {}               # found identifiers

    def is_source(self, label):
        return True

    def is_sink(self, label):
        return True
    
    def is_sanitizer(self, label):
        return True


    def run(self):
        self.dispatcher(self.program)


    def dispatcher(self, node):
        table = {
            'Program':              self.analyse_program,
            'ExpressionStatement':  self.analyse_expression,
            'CallExpression':       self.analyse_call,
            'MemberExpression':     self.analyse_member,
            'Identifier':           self.analyse_identifier,
            'Literal':              self.analyse_literal
        }

        if node['type'] in table:
            table[node['type']](node)
        else:
            print('Node not recognized')


    def analyse_program(self, program_node):
        for instruction in program_node['body']:
            print(instruction)
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
        # magic
        self.dispatcher(callee)
        
        for argument in arguments:
            self.dispatcher(argument)

            tainted_args = []
            if argument['taint'].is_tainted():
                tainted_args += argument

            if len(tainted_args) > 0:
                # calculate sources, path, etc
                call_node['taint'] = Taint(value = True, initial_sources = "TODO", sources_path = "TODO", sanitizers = "TODO", sinks = "TODO")

                if self.is_sink(callee['full_name']):
                    # create vuln
                    self.vulnerabilities += [call_node]
                    print("FOUND VULNERABILITY!!!!!!!!!!!!!!!")


    def analyse_member(self, member_node):
        '''
            type: 'MemberExpression';
            computed: boolean;
            object: Expression;
            property: Expression;
        '''
        print("Member")

    def analyse_identifier(self, identifier_node):
        '''
            type: 'Identifier';
            name: string;
        '''
        name = identifier_node['name']
        print(f'Identifier: {name}')
        identifier_node['taint'] = Taint(value = True, initial_sources = (name,), sources_path = ((name,),), sanitizers = (), sinks = ())

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
        literal_node['taint'] = Taint()



    def report_vulns(self):
        if len(self.vulnerabilities) == 0:
            print('No vulnerabilities found!')
        else:
            print(f'Found vulnerabilities: {len(self.vulnerabilities)}')
            for vuln in self.vulnerabilities:
                print(vuln)