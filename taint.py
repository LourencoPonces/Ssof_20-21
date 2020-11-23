class Taint:
    def __init__(self, value = False, initial_sources = None, sources_path = (), sanitizers = (), sinks = ()):
        self.value = value
        self.initial_sources = initial_sources

        tmp1 = f(source1, source2)
        tmp2 = g(tmp1, source3)
        # ((initial_sourceA -> sourceA2 -> ... -> most_recent_sourceA), (initial_sourceA -> sourceA2 -> ... -> most_recent_sourceA))        
        self.sources_path = sources_path
        self.sanitizers = sanitizers
        self.sinks = sinks
    
    def is_tainted(self):
        return self.value
    
    def get_initial_sources(self):
        return self.initial_sources