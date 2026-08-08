"""Tests for the generic pagination helper."""

import pytest
from sqlalchemy import select

from models.auth import User
from services.pagination import Page, paginate


@pytest.mark.asyncio
async def test_paginate_scalar_empty(db_session):
    query = select(User).where(User.email == "nobody@example.com")
    page = await paginate(db_session, query, per_page=10)
    assert page.items == []
    assert page.total == 0
    assert page.total_pages == 1
    assert page.has_more is False
    assert page.has_next is False
    assert page.has_prev is False


@pytest.mark.asyncio
async def test_paginate_scalar_pages(db_session):
    for i in range(5):
        db_session.add(User(email=f"pager{i}@example.com", is_admin=False))
    await db_session.commit()

    query = select(User).order_by(User.email)
    page = await paginate(db_session, query, page=1, per_page=3)
    assert page.total == 5
    assert page.total_pages == 2
    assert page.has_more is True
    assert page.has_next is True
    assert page.has_prev is False
    assert len(page.items) == 3

    page2 = await paginate(db_session, query, page=2, per_page=3)
    assert len(page2.items) == 2
    assert page2.has_more is False
    assert page2.has_next is False
    assert page2.has_prev is True


@pytest.mark.asyncio
async def test_paginate_tuple_rows(db_session):
    db_session.add(User(email="tuple@example.com", is_admin=False))
    await db_session.commit()

    query = select(User.id, User.email)
    page = await paginate(db_session, query, scalar=False)
    assert page.total == 1
    assert len(page.items) == 1
    assert isinstance(page, Page)


@pytest.mark.asyncio
async def test_paginate_page_beyond_end(db_session):
    db_session.add(User(email="beyond@example.com", is_admin=False))
    await db_session.commit()

    page = await paginate(db_session, select(User), page=99, per_page=10)
    assert page.items == []
    assert page.total == 1
    assert page.page == 99
