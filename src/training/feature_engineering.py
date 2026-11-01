
import re
from datetime import datetime, timezone


SQL_ACTIONS = {
    "select": 1,
    "insert": 2,
    "update": 3,
    "delete": 4,
    "create": 5,
    "alter": 6,
    "drop": 7,
    "grant": 8,
    "revoke": 9,
    "execute": 10,
    "truncate": 11,
}

SQL_KEYWORDS = {
    "select", "insert", "update", "delete",
    "create", "alter", "drop", "truncate",
    "union", "join", "where", "having",
    "group", "order", "by", "from",
    "into", "values", "set", "exec",
    "execute", "grant", "revoke",
}

SUSPICIOUS_SQL_PATTERNS = {
    "has_union": r"\bunion\s+(all\s+)?select\b",
    "has_sleep": r"\b(sleep|benchmark|pg_sleep)\s*\(",
    "has_sql_comment": r"(--|#|/\*)",
    "has_tautology": r"('|\"|\b)\s*or\s+('|\"|\b)?\d+\s*=\s*\d+",
    "has_stacked_query": r";\s*(select|insert|update|delete|drop|alter)\b",
    "has_information_schema": r"\binformation_schema\b",
}

FIELD_ALIASES = {
    "query": [
        "query", "sql", "sql_query", "statement",
        "query_text", "command_text", "full_query",
    ],
    "action": [
        "action", "sql_action", "event", "event_type",
        "operation", "command",
    ],
    "timestamp": [
        "timestamp", "event_time", "time",
        "datetime", "created_at", "logged_at",
    ],
    "status": [
        "status", "result", "outcome", "event_status",
    ],
    "username": [
        "username", "user", "db_user", "account",
    ],
    "source_ip": [
        "src_ip", "source_ip", "client_ip",
        "remote_ip", "ip",
    ],
}


def get_field(record, aliases):
    """Find a field using known alternative column names."""

    normalized = {
        str(key).strip().lower(): value
        for key, value in record.items()
    }

    for alias in aliases:
        if alias in normalized:
            return normalized[alias]

    return None


def parse_timestamp(value):
    """Parse ISO timestamps and return a UTC datetime."""

    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(
                value.strip().replace("Z", "+00:00")
            )
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def extract_sql_action(action, query):
    """Determine a SQL action from the action field or query."""

    if action:
        normalized = str(action).strip().lower()

        for sql_action in SQL_ACTIONS:
            if normalized == sql_action:
                return SQL_ACTIONS[sql_action]

    if query:
        match = re.search(
            r"\b(select|insert|update|delete|create|alter|drop|"
            r"grant|revoke|execute|truncate)\b",
            str(query),
            flags=re.IGNORECASE,
        )

        if match:
            return SQL_ACTIONS.get(match.group(1).lower(), 0)

    return 0


def extract_features(record):
    """
    Convert one audit-log record into numeric ML features.

    The function does not assign an attack/normal label.
    """

    if not isinstance(record, dict):
        raise TypeError("Record must be a dictionary")

    query_value = get_field(record, FIELD_ALIASES["query"])
    action_value = get_field(record, FIELD_ALIASES["action"])
    timestamp_value = get_field(record, FIELD_ALIASES["timestamp"])
    status_value = get_field(record, FIELD_ALIASES["status"])
    username_value = get_field(record, FIELD_ALIASES["username"])
    ip_value = get_field(record, FIELD_ALIASES["source_ip"])

    query = str(query_value or "").strip()
    query_lower = query.lower()

    action_code = extract_sql_action(action_value, query)

    timestamp = parse_timestamp(timestamp_value)

    status = str(status_value or "").strip().lower()

    username = str(username_value or "").strip()
    source_ip = str(ip_value or "").strip()

    tokens = re.findall(r"\b[a-z_][a-z0-9_]*\b", query_lower)

    features = {
        # SQL behavior
        "sql_action_code": action_code,
        "query_length": len(query),
        "query_word_count": len(tokens),
        "sql_keyword_count": sum(
            token in SQL_KEYWORDS for token in tokens
        ),
        "has_where": int(bool(re.search(r"\bwhere\b", query_lower))),
        "has_join": int(bool(re.search(r"\bjoin\b", query_lower))),
        "has_subquery": int(
            query_lower.count("select") > 1
        ),

        # Potentially suspicious SQL patterns.
        # These are indicators, not attack verdicts.
        "has_union": int(
            bool(re.search(
                SUSPICIOUS_SQL_PATTERNS["has_union"],
                query_lower
            ))
        ),
        "has_sleep": int(
            bool(re.search(
                SUSPICIOUS_SQL_PATTERNS["has_sleep"],
                query_lower
            ))
        ),
        "has_sql_comment": int(
            bool(re.search(
                SUSPICIOUS_SQL_PATTERNS["has_sql_comment"],
                query_lower
            ))
        ),
        "has_tautology": int(
            bool(re.search(
                SUSPICIOUS_SQL_PATTERNS["has_tautology"],
                query_lower
            ))
        ),
        "has_stacked_query": int(
            bool(re.search(
                SUSPICIOUS_SQL_PATTERNS["has_stacked_query"],
                query_lower
            ))
        ),
        "has_information_schema": int(
            bool(re.search(
                SUSPICIOUS_SQL_PATTERNS["has_information_schema"],
                query_lower
            ))
        ),

        # Authentication and result status.
        "is_failed": int(
            any(word in status for word in (
                "fail", "denied", "error", "reject"
            ))
        ),
        "is_success": int(
            any(word in status for word in (
                "success", "accepted", "ok"
            ))
        ),

        # Basic identity metadata.
        "username_present": int(bool(username)),
        "source_ip_present": int(bool(source_ip)),
        "username_length": len(username),
    }

    # Time-based features.
    if timestamp:
        features.update({
            "hour_utc": timestamp.hour,
            "day_of_week": timestamp.weekday(),
            "is_weekend": int(timestamp.weekday() >= 5),
            "is_night": int(
                timestamp.hour < 6 or timestamp.hour >= 22
            ),
            "timestamp_valid": 1,
        })
    else:
        features.update({
            "hour_utc": 0,
            "day_of_week": 0,
            "is_weekend": 0,
            "is_night": 0,
            "timestamp_valid": 0,
        })

    return features


def transform_records(records):
    """Convert a list of audit-log records into ML feature rows."""

    if not isinstance(records, list):
        raise TypeError("Records must be a list")

    return [
        extract_features(record)
        for record in records
    ]
