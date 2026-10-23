from __future__ import annotations
from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class InnerHttpRequest:
    method: str
    path: str
    insurant_id: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass(frozen=True)
class InnerHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: object
    status_line: str

    def as_legacy_dict(self) -> dict:
        return {"http_status": self.status_line, "headers": dict(self.headers), "body": self.body}
