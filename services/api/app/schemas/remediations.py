import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RemediationIterationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    round_no: int | None
    candidate_hash: str | None
    candidate_code: str | None
    test_results: dict
    rescan_diff: dict
    failure_output: str | None
    fix_source: str | None
    fix_note: str | None
    created_at: datetime


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    status: str
    finding_status: str
    cancel_requested: bool
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    iterations: list[RemediationIterationOut] = []
