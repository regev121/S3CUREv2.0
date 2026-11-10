from pydantic import BaseModel


class GroupMembershipRequest(BaseModel):
    username: str
    group_name: str
