class Sanitizer:
    def __init__(self, identifier,  patterns = []):
        self.identifier = identifier
        self.tracked_patterns = {}
        for pattern in patterns:
            pat_name = pattern.get_name()
            self.tracked_patterns[pat_name] = {
                'pattern': pattern,
                'sources': [],
                'sinks': [],
                'sanitizers': [identifier]
            }
    
    def get_tracked_patterns(self):
        return [self.tracked_patterns]
    
    def __repr__(self):
        return f'<Sanitizer {self.identifier}, {len(self.tracked_patterns)}>'