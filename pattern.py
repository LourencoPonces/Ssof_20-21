class Pattern:
    def __init__(self, pattern_json):
        self.name = pattern_json['vulnerability']
        self.sources = pattern_json['sources']
        self.sanitizers = pattern_json['sanitizers']
        self.sinks = pattern_json['sinks']
    
    def get_name(self):
        return self.name
    
    def detect_source(self, potential):
        return (potential in self.sources)

    def detect_sanitizer(self, potential):
        return (potential in self.sanitizers)

    def detect_sink(self, potential):
        return (potential in self.sinks)

    def __repr__(self):
        obj = {
            'vulnerability': self.name,
            'sources': self.sources,
            'sanitizers': self.sanitizers,
            'sinks': self.sinks
        }
        return f"<Pattern {self.name}>"