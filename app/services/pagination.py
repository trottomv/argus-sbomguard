from dataclasses import dataclass
from typing import TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")


# Default page sizes for HTML views and API routes
VULN_PER_PAGE = 50
SBOM_PER_PAGE = 50
PROJECT_PER_PAGE = 25
PROJECT_SBOM_HISTORY_PER_PAGE = 3
PROJECT_VULN_PER_PAGE = 25
ALERT_PER_PAGE = 25


@dataclass
class Page:
    items: list
    total: int
    page: int
    per_page: int
    total_pages: int
    has_more: bool

    @property
    def has_next(self) -> bool:
        return self.has_more

    @property
    def has_prev(self) -> bool:
        return self.page > 1


async def paginate(
    db: AsyncSession,
    query,
    page: int = 1,
    per_page: int = 50,
    *,
    scalar: bool = True,
) -> Page:
    count_subq = query.order_by(None).subquery()
    total = (await db.execute(select(func.count()).select_from(count_subq))).scalar() or 0
    total_pages = max(1, (total + per_page - 1) // per_page)

    offset = max(0, (page - 1) * per_page)
    result = await db.execute(query.offset(offset).limit(per_page + 1))

    all_items = result.scalars().all() if scalar else result.all()

    has_more = len(all_items) > per_page
    items = all_items[:per_page]

    return Page(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        has_more=has_more,
    )
