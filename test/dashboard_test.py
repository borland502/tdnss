"""Tests for :mod:`tdnss.dashboard`."""
from tdnss.connection import Connection


def test_get_stats():
    conn = Connection()
    r = conn.login()

    if not r.is_ok():
        raise ValueError("Login error")

    r = conn.dashboard_api().get_stats("LastHour")

    if r.is_ok():
        print(r.data)
    else:
        raise ValueError()


def test_get_top_stats():
    conn = Connection()
    r = conn.login()

    if not r.is_ok():
        raise ValueError("Login error")

    r = conn.dashboard_api().get_top_stats("TopClients")

    if r.is_ok():
        print(r.data)
    else:
        raise ValueError()


def test_delete_stats():
    conn = Connection()
    r = conn.login()

    if not r.is_ok():
        raise ValueError("Login error")

    r = conn.dashboard_api().delete_stats()

    if r.is_ok():
        print(r.message)
    else:
        raise ValueError()
