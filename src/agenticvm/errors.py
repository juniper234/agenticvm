class AgenticVMError(Exception):
    """An actionable controller or guest error."""

    def __init__(self, message: str, code: str = "controller_error", details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details


class GuestError(AgenticVMError):
    pass
