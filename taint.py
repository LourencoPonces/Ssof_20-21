class Taint:
    def __init__(self, value = False, initial_sources = None, sources_path = (), sanitizers = (), sinks = ()):
        self.value = value
        self.initial_sources = initial_sources
        self.sources_path = sources_path
        self.sanitizers = sanitizers
        self.sinks = sinks
    
    def is_tainted(self):
        return self.value