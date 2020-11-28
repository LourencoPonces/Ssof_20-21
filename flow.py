from vulnerability import Vulnerability

class Flow:
    def __init__(self, previous_flows):
        # What originated this flow (other Flows or Sources)
        # [Flow / Source, ...]
        self.previous_flows = previous_flows

        # Shortcut for every flow leaf
        # [Source, ...]
        self.sources = []

        # List of sanitizers per pattern
        self.sanitizers = {}

        for flow in previous_flows:
            # Some of these flows might be a Source. Magic...
            self.sources += flow.get_sources()
            for pat_name, sanitizers in flow.get_sanitizers().items():
                if pat_name not in self.sanitizers:
                    self.sanitizers[pat_name] = []
                
                for sanitizer in sanitizers:
                    if sanitizer not in self.sanitizers[pat_name]:
                        self.sanitizers[pat_name].append(sanitizer)

    def is_tainted(self):
        return len(self.sources) > 0

    def get_sources(self):
        return self.sources

    def get_sanitizers(self):
        return self.sanitizers

    def check_sanitizer(self, sanitizer_name, arguments):
        for argument in arguments:
            for source in argument['flow'].get_sources():
                found_patterns = source.check_sanitizer(sanitizer_name)
                for pattern in found_patterns:
                    pattern_name = pattern.get_name()

                    if pattern_name not in self.sanitizers:
                        self.sanitizers[pattern_name] = []
                    
                    if sanitizer_name not in self.sanitizers[pattern_name]:
                        self.sanitizers[pattern_name].append(sanitizer_name)

    def check_sink(self, sink_name):
        matching_patterns = {}
        for source in self.sources:
            found_patterns = source.check_sink(sink_name)

            # merge multiple sources for the same pattern
            for pattern in found_patterns:
                pattern_name = pattern.get_name()
                
                if pattern_name in matching_patterns:
                    pattern = matching_patterns[pattern_name]
                else:
                    pattern = {
                        'name': pattern_name,
                        'sources': []
                    }
                    matching_patterns[pattern_name] = pattern
                
                pattern['sources'].append(source.get_identifier())
        
        vulns = []
        for pattern in matching_patterns.values():
            name = pattern['name']
            sources = pattern['sources']
            sanitizers = []
            if name in self.sanitizers:
                sanitizers = self.sanitizers[name]
            
            sinks = [sink_name]
            vuln = Vulnerability(name, sources, sanitizers, sinks)
            vulns.append(vuln)
        return vulns

    def __repr__(self):
        return f'<Flow from {self.sources.__repr__()}>'
    
    def __str__(self):
        obj = {
            'type': 'flow',
            'previous_flows': [flow for flow in self.previous_flows],
            'sources': [source for source in self.sources]
        }
        return obj.__str__()