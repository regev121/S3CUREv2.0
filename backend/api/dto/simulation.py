from pydantic import BaseModel
from typing import List


class SimulationRequest(BaseModel):
    username: str
    add_policies: List[str] = []
    remove_policies: List[str] = []
    add_groups: List[str] = []
    remove_groups: List[str] = []
