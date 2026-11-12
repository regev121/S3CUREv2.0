from pydantic import BaseModel, Field


class RiskRule(BaseModel):
    id: str | None = None
    description: str = Field(min_length=1)
    severity: int = Field(ge=0)
    resource_pattern: str = Field(min_length=1)
    risky_actions: list[str] = Field(min_length=1)
    require_global_grant: bool | None = None


class RiskRulesUpdate(BaseModel):
    risk_rules: list[RiskRule]
