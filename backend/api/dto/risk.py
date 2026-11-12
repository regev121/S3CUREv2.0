from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from backend.core.graphLoader.policyParser import statement_scope


Pattern = Annotated[str, StringConstraints(min_length=1, pattern=r"^[^\x00]+$")]
ActionPattern = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^(\*+|[A-Za-z0-9*?-]+:[A-Za-z0-9*?-]+)$")]
ConditionValue = str | bool | int | float


class PolicyStatement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    Sid: str | None = None
    Effect: Literal["Allow", "Deny"]
    Action: ActionPattern | list[ActionPattern] | None = None
    NotAction: ActionPattern | list[ActionPattern] | None = None
    Resource: Pattern | list[Pattern] | None = None
    NotResource: Pattern | list[Pattern] | None = None
    Condition: dict[str, dict[str, ConditionValue | list[ConditionValue]]] | None = None

    @model_validator(mode="after")
    def validate_scope(self):
        if bool(self.Action) == bool(self.NotAction):
            raise ValueError("Supply either Action or NotAction.")
        if self.Resource and self.NotResource:
            raise ValueError("Supply either Resource or NotResource.")
        if not statement_scope(self.model_dump())["resources"]:
            raise ValueError("Supply Resource or NotResource for this action.")
        return self


class RiskPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    Version: str | None = None
    Id: str | None = None
    Statement: PolicyStatement | Annotated[list[PolicyStatement], Field(min_length=1)]


class RiskRule(BaseModel):
    id: str | None = None
    description: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    severity: int = Field(ge=0)
    resource_pattern: Pattern | None = None
    risky_actions: list[Pattern] | None = None
    require_global_grant: bool | None = None
    policy: RiskPolicy | None = None
    source_policy: str | None = None
    category: str | None = None

    @model_validator(mode="after")
    def validate_rule(self):
        if self.policy:
            if self.resource_pattern or self.risky_actions or self.require_global_grant:
                raise ValueError("Use either a policy document or the guided action and resource fields.")
            if self.id == "R001" or self.description == "CRITICAL: Public Access to Production Data":
                raise ValueError("The anonymous access rule uses the guided fields.")
        elif not self.resource_pattern or not self.risky_actions:
            raise ValueError("Enter at least one action and a resource pattern.")
        return self


class RiskRulesUpdate(BaseModel):
    risk_rules: list[RiskRule]
    base_revision: str | None = None

    @model_validator(mode="after")
    def unique_ids(self):
        ids = [rule.id for rule in self.risk_rules if rule.id]
        if len(ids) != len(set(ids)):
            raise ValueError("Rule IDs must be unique.")
        return self
