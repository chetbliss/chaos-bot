"""Structured JSON logging for chaos-bot."""

import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Emit log records as JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": getattr(record, "bot_module", record.module),
            "vlan_id": getattr(record, "vlan_id", None),
            "source_ip": getattr(record, "source_ip", None),
            "target_ip": getattr(record, "target_ip", None),
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


# In-memory buffer for web UI log streaming
_log_buffer: list[str] = []
_log_buffer_max = 1000


class BufferHandler(logging.Handler):
    """Store log lines in memory for SSE streaming."""

    def emit(self, record: logging.LogRecord) -> None:
        line = self.format(record)
        _log_buffer.append(line)
        if len(_log_buffer) > _log_buffer_max:
            _log_buffer.pop(0)


def get_log_buffer() -> list[str]:
    """Return current log buffer."""
    return list(_log_buffer)


def setup_logging(level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    """Configure structured JSON logging."""
    logger = logging.getLogger("chaos_bot")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    fmt = JsonFormatter()

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(fmt)
    logger.addHandler(stdout_handler)

    buffer_handler = BufferHandler()
    buffer_handler.setFormatter(fmt)
    logger.addHandler(buffer_handler)

    if log_file:
        from pathlib import Path
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    """Get the chaos_bot logger (must call setup_logging first)."""
    return logging.getLogger("chaos_bot")
