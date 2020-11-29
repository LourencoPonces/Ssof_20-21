class Sink:
    def __init__(self, identifier,  patterns = []):
        self.tracked_patterns = {}
        for pattern in patterns:
            pat_name = pattern.get_name()
            self.tracked_patterns[pat_name] = {
                'pattern': pattern,
                'sources': [],
                'sinks': [identifier],
                'sanitizers': []
            }
    
    def get_tracked_patterns(self):
        return self.tracked_patterns