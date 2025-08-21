from pydantic import BaseModel, ConfigDict

def to_camel(string: str) -> str:
    """Converts snake_case_string to camelCaseString."""
    return ''.join(word.capitalize() for word in string.split('_'))

class DashboardSummaryStats(BaseModel):
    # Your model fields remain in snake_case for Python
    total_logs: int
    total_alerts: int
    active_alerts: int
    anomalies_detected: int

    # This config tells Pydantic to convert to camelCase for the JSON output
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True, # Allows both snake_case and camelCase for input
    )