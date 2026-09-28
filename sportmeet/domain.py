"""Domain policies shared by the web layer.

Abstract role contract + specialized roles demonstrate polymorphic access control.
TrainingSlot encapsulates the time interval used by the scheduling policy.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta


class RolePolicy(ABC):
    @property
    @abstractmethod
    def role(self) -> str:
        """Name stored in the users table."""

    @property
    @abstractmethod
    def permissions(self) -> frozenset[str]:
        """Business actions available to the role."""

    def allows(self, permission: str) -> bool:
        return permission in self.permissions


class ParticipantPolicy(RolePolicy):
    role = "participant"
    permissions = frozenset({"catalog", "join", "leave", "review", "report",
                             "propose", "notifications"})


class OrganizerPolicy(RolePolicy):
    role = "organizer"
    permissions = frozenset({"catalog", "organize", "report", "create_session",
                             "own_sessions", "applications", "attendance",
                             "organization_profile", "demand", "notifications"})


class VenueAdminPolicy(RolePolicy):
    role = "venue_admin"
    permissions = frozenset({"catalog", "moderate_venues", "venue_reports",
                             "venue_edits", "venue_export", "notifications"})


class EventAdminPolicy(RolePolicy):
    role = "event_admin"
    permissions = frozenset({"catalog", "moderate_events", "organizations",
                             "publish_sessions", "applications", "attendance",
                             "reviews_moderation", "organization_profile",
                             "demand", "notifications"})


class GlobalAdminPolicy(RolePolicy):
    role = "global_admin"
    permissions = frozenset({"catalog", "moderate_venues", "moderate_events", "system",
                             "venue_reports", "venue_edits", "venue_export",
                             "organizations", "publish_sessions", "applications",
                             "attendance", "reviews_moderation", "organization_profile",
                             "role_assign", "system_export", "demand", "notifications"})


POLICIES = {policy.role: policy for policy in (
    ParticipantPolicy(), OrganizerPolicy(), VenueAdminPolicy(),
    EventAdminPolicy(), GlobalAdminPolicy())}
ROLE_PERMISSION = {
    "participant": "join", "organizer": "organize", "venue_admin": "moderate_venues",
    "event_admin": "moderate_events", "global_admin": "system",
}

ROLE_LABELS = {
    "guest": "Гость", "participant": "Участник", "organizer": "Организатор",
    "venue_admin": "Администратор площадок",
    "event_admin": "Администратор мероприятий",
    "global_admin": "Глобальный администратор",
}

CAPABILITY_LABELS = {
    "catalog": "Искать встречи и площадки, пользоваться фильтрами и картой",
    "join": "Подавать заявки на встречи и вставать в очередь",
    "leave": "Отменять свои заявки и записи",
    "review": "Оставлять отзыв после отмеченного посещения",
    "report": "Сообщать о неточностях в карточках площадок",
    "propose": "Предлагать занятие по спорту и району",
    "demand": "Изучать предложения жителей по видам спорта и районам",
    "create_session": "Создавать разовые и еженедельные встречи от подтверждённой организации",
    "own_sessions": "Переносить и отменять собственные встречи",
    "applications": "Рассматривать заявки участников в своей зоне ответственности",
    "attendance": "Отмечать присутствие на доступных мероприятиях",
    "organization_profile": "Обновлять описание доступной организации",
    "venue_reports": "Разбирать сообщения о площадках и управлять видимостью карточек",
    "venue_edits": "Исправлять площадки с сохранением истории",
    "venue_export": "Выгружать сведения о площадках",
    "organizations": "Проверять организации и принадлежность организаторов",
    "publish_sessions": "Публиковать, отклонять и отменять встречи",
    "reviews_moderation": "Модерировать отзывы о встречах",
    "role_assign": "Назначать роли другим пользователям",
    "system_export": "Выгружать сводные данные о встречах",
    "notifications": "Читать личные уведомления",
}

PUBLIC_FEATURES = (
    "Искать и фильтровать площадки и опубликованные встречи",
    "Открывать карточки площадок и организаций",
    "Смотреть даты встреч на карте",
)


@dataclass(frozen=True)
class TrainingSlot:
    start: datetime
    minutes: int

    @classmethod
    def from_values(cls, start: str, minutes: int) -> "TrainingSlot":
        return cls(datetime.fromisoformat(start), minutes)

    @property
    def end(self) -> datetime:
        return self.start + timedelta(minutes=self.minutes)

    def overlaps(self, other: "TrainingSlot") -> bool:
        return self.start < other.end and other.start < self.end


class SchedulePolicy:
    def __init__(self, existing_slots: list[TrainingSlot]):
        self._existing_slots = tuple(existing_slots)

    def has_conflict(self, candidate: TrainingSlot) -> bool:
        return any(candidate.overlaps(slot) for slot in self._existing_slots)
