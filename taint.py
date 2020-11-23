class Taint:
    def __init__(self, value = False, initial_sources = None, sanitizers = (), sinks = ()):
        self.value = value
        self.initial_sources = initial_sources
        self.sanitizers = sanitizers
        self.sinks = sinks
    
    def is_tainted(self):
        return self.value
    
    def get_initial_sources(self):
        return self.initial_sources
    
    def get_sanitizers(self):
        return self.sanitizers

    def get_sinks(self):
        return self.sinks