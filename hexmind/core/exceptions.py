"""Custom exception hierarchy for HexMind error handling."""


class HexMindError(Exception):
    """Base exception for all HexMind errors."""


class ToolExecutionError(HexMindError):
    """Raised when a recon tool fails to execute or returns an error."""


class AIError(HexMindError):
    """Raised when the AI engine encounters an unrecoverable error."""


class DatabaseError(HexMindError):
    """Raised when a database operation fails."""


class ValidationError(HexMindError):
    """Raised when target or input validation fails."""


class OllamaNotRunningError(AIError):
    """Raised when the Ollama service is not reachable."""


class ModelNotFoundError(AIError):
    """Raised when the requested model is not pulled in Ollama."""


class OllamaTimeoutError(AIError):
    """Raised when an Ollama request exceeds the configured timeout."""


class ToolNotFoundError(ToolExecutionError):
    """Raised when a required system binary is not found on PATH."""


class ToolTimeoutError(ToolExecutionError):
    """Raised when a tool run exceeds its timeout limit."""
