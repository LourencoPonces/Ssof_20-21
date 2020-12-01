from vulnerability import Vulnerability
from itertools import product

class Flow:
    def __init__(self, previous_flows):

        # List of tracked Sources, Sinks and Sanitizers per pattern
        # {
        #   pattern_name : {
        #       pattern: Pattern,
        #       sources : [source, ...],
        #       sinks: [sink, ...],
        #       sanitizers: [sanitizer, ...]
        #   }
        # }

        self.tracked_patterns = []
        
        all_flows = [flow.get_tracked_patterns() for flow in previous_flows if len(flow.get_tracked_patterns()) > 0]
        all_combs = product(*all_flows)

        for combination in all_combs:
            comb_pattern = {}
            for pat in combination:
                for pat_name, tracked in pat.items():
                    if pat_name not in comb_pattern:
                        comb_pattern[pat_name] = tracked.copy()
                    else:
                        # Pattern already exists. Adding unique sources/sinks/sanitizers
                        known_sources = comb_pattern[pat_name]['sources']                    
                        known_sinks = comb_pattern[pat_name]['sinks']
                        known_sanitizers = comb_pattern[pat_name]['sanitizers']

                        for source in tracked['sources']:
                            if source not in known_sources:
                                known_sources.append(source)
                        
                        for sink in tracked['sinks']:
                            if sink not in known_sinks:
                                known_sinks.append(sink)
                        
                        for sanitizer in tracked['sanitizers']:
                            if sanitizer not in known_sanitizers:
                                known_sanitizers.append(sanitizer)
            self.tracked_patterns.append(comb_pattern)


    def get_tracked_patterns(self):
        return self.tracked_patterns

    def remove_sanitizers(self):
        for possible_flow in self.tracked_patterns:
            for tracked in possible_flow.values():
                tracked['sanitizers'] = []

    def remove_sinks(self):
        for possible_flow in self.tracked_patterns:
            for tracked in possible_flow.values():
                tracked['sinks'] = []
    
    def remove_sources(self):
        for possible_flow in self.tracked_patterns:
            for tracked in possible_flow.values():
                tracked['sources'] = []

    def check_vulns(self):
        vulns = []
        for possible_flow in self.tracked_patterns:
            for pat_name, tracked in possible_flow.items():
                if len(tracked['sources']) > 0 and len(tracked['sinks']) > 0:
                    for sink in tracked['sinks']:
                        # [:] makes a copy of the array, so the reported vuln isn't changed
                        # after being reported
                        vuln_name = pat_name
                        src = tracked['sources'][:]
                        san = tracked['sanitizers'][:]
                        snk = [sink][:]
                        vulns.append(Vulnerability(vuln_name, src, san, snk))
                    # clear already reported sinks
                    tracked['sinks'] = []
        return vulns

    def __repr__(self):
        return f"<Flow {self.tracked_patterns}>"