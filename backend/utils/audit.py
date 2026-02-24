"""
Security audit logging helpers.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

audit_logger = logging.getLogger("audit")


def log_security_event(
    event_type: str,
    *,
    success: bool,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Emit structured audit log entries for security-relevant actions.
    """
    record: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "success": success,
    }
    if user_id:
        record["user_id"] = user_id
    if username:
        record["username"] = username
    if ip_address:
        record["ip"] = ip_address
    if details:
        record["details"] = details

    audit_logger.info(json.dumps(record, separators=(",", ":"), sort_keys=True))
