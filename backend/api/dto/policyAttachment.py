from pydantic import BaseModel


class PolicyAttachmentRequest(BaseModel):
    username: str
    policy_name: str
