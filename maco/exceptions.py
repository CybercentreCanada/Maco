"""Exception classes for extractors."""


# Can be raised by extractors to abort analysis of a sample
# ie. Can abort if preliminary checks at start of run indicate the file shouldn't be analyzed by extractor
class AnalysisAbortedException(Exception):
    """Raised when extractors voluntarily abort analysis of a sample."""

    pass


class ExtractorLoadError(Exception):
    """Raised when extractors cannot be loaded."""

    pass


class InvalidExtractor(ValueError):
    """Raised when an extractor is invalid."""

    pass


class NoHitException(Exception):
    """Raised when the YARA rule of an extractor doesn't hit."""

    pass


class SyntaxError(Exception):
    """Raised when there's a syntax error in the YARA rule."""

    pass
