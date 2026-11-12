from pydantic import BaseModel, IPvAnyAddress


class RequestContext(BaseModel):
    source_ip: IPvAnyAddress | None = None
    secure_transport: bool | None = None
    s3_prefix: str | None = None

    def policy_values(self):
        return {
            key: value
            for key, value in (
                ("aws:sourceip", self.source_ip),
                ("aws:securetransport", self.secure_transport),
                ("s3:prefix", self.s3_prefix),
            )
            if value is not None
        }


class SimulationRequest(BaseModel):
    username: str
    add_policies: list[str] = []
    remove_policies: list[str] = []
    add_groups: list[str] = []
    remove_groups: list[str] = []
    context: RequestContext | None = None
