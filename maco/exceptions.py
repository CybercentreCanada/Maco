"""Exception classes for extractors."""


# Can be raised by extractors to abort analysis of a sample
# ie. Can abort if preliminary checks at start of run indicate the file shouldn't be analyzed by extractor
class AnalysisAbortedException(Exception):
    """Raised when extractors voluntarily abort analysis of a sample."""


class ExtractorLoadError(Exception):
    """Raised when extractors cannot be loaded."""


class InvalidExtractor(ValueError):
    """Raised when an extractor is invalid."""


class NoHitException(Exception):
    """Raised when the YARA rule of an extractor doesn't hit."""


class SyntaxError(Exception):
    """Raised when there's a syntax error in the YARA rule."""
