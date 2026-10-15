"""Request context passed to services: who acts, through which channel, from where."""
from __future__ import annotations

from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
class Actor:
    kind: str  # user | service | system | anonymous | owner
    name: str = ""
    role: str = ""
    user_id: int | None = None

    @property
    def is_owner(self) -> bool:
        return self.kind == "owner"


SYSTEM_ACTOR = Actor(kind="system", name="System")
ANONYMOUS_ACTOR = Actor(kind="anonymous", name="")


@dataclass(frozen=True)
class RequestContext:
    actor: Actor = field(default=SYSTEM_ACTOR)
    channel: str = "api"  # ui | api | service | cli | scheduler | dev-loginless
    source_ip: str = ""
    user_agent: str = ""
    request_id: str = ""
    session_ref: str = ""

    def with_actor(self, actor: Actor) -> "RequestContext":
        return replace(self, actor=actor)


def system_context(channel: str = "cli") -> RequestContext:
    return RequestContext(actor=SYSTEM_ACTOR, channel=channel)
