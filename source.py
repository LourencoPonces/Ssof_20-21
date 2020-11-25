from vulnerability import Vulnerability

class Source:
    def __init__(self, identifier = "",  patterns = []):
        self.identifier = identifier  # Source identifier (String)
        self.patterns = patterns      # [Pattern , ...]

    # Used by Flow
    def get_sources(self):
        return [self]

    def get_identifier(self):
        return self.identifier

    def check_sink(self, sink_name):
        patterns = []
        for pattern in self.patterns:
            if pattern.detect_sink(sink_name):
                patterns.append(pattern)
        return patterns