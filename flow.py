from vulnerability import Vulnerability

class Flow:
    def __init__(self, previous_flows):
        # What originated this flow (other Flows or Sources)
        # [Flow / Source, ...]
        self.previous_flows = previous_flows

        # Shortcut for every flow leaf
        # [Source, ...]
        self.sources = []

        for flow in previous_flows:
            # Some of these flows might be a Source. Magic...
            self.sources += flow.get_sources()

    def is_tainted(self):
        return len(self.sources) > 0

    def get_sources(self):
        return self.sources
    
    def check_sink(self, sink_name):
        matching_patterns = {}
        for source in self.sources:
            found_patterns = source.check_sink(sink_name)
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
            sinks = [sink_name]
            vuln = Vulnerability(name, sources, sanitizers, sinks)
            vulns.append(vuln)
        return vulns
