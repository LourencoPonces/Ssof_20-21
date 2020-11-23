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
            'Program':                  self.analyse_program,
            'ExpressionStatement':      self.analyse_expression,
            'CallExpression':           self.analyse_call,
            'MemberExpression':         self.analyse_member_expression,
            'AssignementExpression':    self.analyse_assignement,
            'Identifier':               self.analyse_identifier,
            'Literal':                  self.analyse_literal
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
        
        tainted_args = []
        for argument in arguments:
            self.dispatcher(argument)
            if argument['taint'].is_tainted():
                tainted_args += [argument]
        

        if len(tainted_args) > 0:
            #  TODO: flaten this
            initial_sources = tuple(tainted_arg['taint'].get_initial_sources() for tainted_arg in tainted_args)
            sanitizers = tuple(tainted_arg['taint'].get_sanitizers() for tainted_arg in tainted_args)

            # calculate sources, path, etc
            call_node['taint'] = Taint(value = True, initial_sources = initial_sources, sanitizers = sanitizers, sinks = "TODO")

            # TODO: We need to consider multiple sources in a single sink:
            # sink(source1, source2) will have to report 2 vulnerabilities
            if self.is_sink(callee['full_name']):
                sink = callee['full_name']
                self.vulnerabilities += [call_node]
                print("FOUND VULNERABILITY!!!!!!!!!!!!!!!")

            # TODO: verify if it is sanitizer

    def analyse_member_expression(self, member_node):
        '''
            type: 'MemberExpression';
            computed: boolean;
            object: Expression;
            property: Expression;
        '''
        print("Member Expression")
        
        obj = member_node['object']
        print(f'Object: {obj}')

        prop = member_node['prop']
        print(f'Property: {prop}')

        # TODO: Check when computed is True & False
        
        self.dispatcher(prop)
        self.dispatcher(obj)

    def analyse_assignement(self, assignment_node):
        '''
            type: 'AssigmentExpression';
            operator: ;
            left: Identifier;
            right: Identifier;
        '''
        left = assignment_node['left']
        right = assignment_node['right']
        self.dispatcher(left)
        self.dispatcher(right)
        
        
        
        assignment_node['taint'] = Taint(
            value = right['taint'].is_tainted(),
            initial_sources = right['taint'].get_initial_sources(),
            sanitizers = right['taint'].get_sanitizers(),
            sinks = right['taint'].get_sinks())          # count for nested assignments: a = (b = source)
        
        left['taint'] = Taint(
            value = right['taint'].is_tainted(),
            initial_sources = right['taint'].get_initial_sources(),
            sanitizers = right['taint'].get_sanitizers(),
            sinks = right['taint'].get_sinks())
        #TODO propagar taintdness do lado direito para o lado esquerdo
        

    def analyse_identifier(self, identifier_node):
        '''
            type: 'Identifier';
            name: string;
        '''
        name = identifier_node['name']
        print(f'Identifier: {name}')
        identifier_node['taint'] = Taint(value = True, initial_sources = (name,), sanitizers = (), sinks = ())

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