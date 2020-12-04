from vulnerability import Vulnerability
from itertools import product
from copy import deepcopy
from util import sort_dict

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

        self.reported_vuls = []
        # previous_flows = deepcopy(previous_flows)

        # remove redundant flows
        all_flows = []
        for flow in previous_flows:
            tp = flow.get_tracked_patterns()
            flow_patterns = []
            for possible_pattern in tp: # for every {} in [ {} , ... ]
                copy = {}
                for pat_name, tracked in possible_pattern.items():
                    src = tracked['sources']
                    snk = tracked['sinks']
                    snt = tracked['sanitizers']
                    if len(src + snk + snt) > 0:
                        copy[pat_name] = deepcopy(tracked)
                if len(copy.keys()) > 0:
                    flow_patterns.append(copy)
            if len(flow_patterns) > 0:
                all_flows.append(flow_patterns)

        if len(all_flows) == 0:
            self.tracked_patterns = [{}]
            return

        # all_flows = [flow.get_tracked_patterns() for flow in previous_flows if len(flow.get_tracked_patterns()) > 0]
        # WARNING: These combinations point to the same lists!
        all_combs = product(*all_flows)

        for combination in all_combs:
            comb_pattern = {}
            for pat in combination:
                for pat_name, tracked in pat.items():
                    if pat_name not in comb_pattern:
                        comb_pattern[pat_name] = deepcopy(tracked)
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
                        
                        vuln = Vulnerability(vuln_name, src, san, snk)
                        duplicated = False

                        for rv in self.reported_vuls:
                            duplicated = False
                            if str(rv) == str(vuln):
                                duplicated = True
                                break
                        if not duplicated:
                            self.reported_vuls.append(vuln)
                            vulns.append(vuln)
                    # clear already reported sinks
                    tracked['sinks'] = []
        return vulns

    def merge(self, other_flow):
        changed = False
        incoming_patterns = deepcopy(other_flow.get_tracked_patterns())

        if len(incoming_patterns) == 1 and incoming_patterns[0] == {}:
            # if incoming is empty, did not change
            return False

        if len(self.tracked_patterns) == 1 and self.tracked_patterns[0] == {}:
            # empty patterns: new patterns = incoming!
            self.tracked_patterns = incoming_patterns
            return True

        # TODO: avoid duplicate patterns
        for pattern in incoming_patterns:
            matches_any = False
            sorted_incoming_pattern = sort_dict(pattern)
            for our_pattern in self.tracked_patterns:
                sorted_our_pattern = sort_dict(our_pattern)
                # since they are sorted, the str will produce the same string
                if str(sorted_incoming_pattern) == str(sorted_our_pattern):
                    matches_any = True
                    break

            if not matches_any:
                self.tracked_patterns.append(pattern)
                changed = True

        return changed

    def __repr__(self):
        return f"<Flow {self.tracked_patterns}>"
