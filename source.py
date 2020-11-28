from vulnerability import Vulnerability

class Source:
    def __init__(self, identifier = "",  patterns = []):
        self.identifier = identifier  # Source identifier (String)
        self.patterns = patterns      # [Pattern , ...]

    def __repr__(self):
        return f"<Source: {self.identifier}>"

    # Used by Flow
    def get_sources(self):
        return [self]
    
    def get_sanitizers(self):
        return {}

    def get_identifier(self):
        return self.identifier

    def check_sink(self, sink_name):
        patterns = []
        for pattern in self.patterns:
            if pattern.detect_sink(sink_name):
                patterns.append(pattern)
        return patterns
    
    def check_sanitizer(self, sanitizer_name):
        patterns = []
        for pattern in self.patterns:
            if pattern.detect_sanitizer(sanitizer_name):
                patterns.append(pattern)
        return patterns

    def __repr__(self):
        obj = {
            'type': 'source',
            'identifier': self.identifier,
            'patterns': [pattern.get_name() for pattern in self.patterns]
        }
        return obj.__repr__()