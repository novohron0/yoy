import asyncio
import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import AsyncMock, patch

import web


def interval_rule(rule_id, pid, *, next_fire=None, minutes=30):
    return {
        "id": rule_id,
        "profile_id": pid,
        "owner": f"owner-{pid}",
        "enabled": True,
        "targets": [{"id": 1, "name": "test", "kind": "chat"}],
        "text": "test",
        "interval_min": minutes,
        "interval_max": minutes,
        "next_fire": next_fire,
        "time": None,
        "weekdays": [],
        "dates": [],
    }


def daily_rule(rule_id, pid, *, time="12:00"):
    return {
        "id": rule_id,
        "profile_id": pid,
        "owner": f"owner-{pid}",
        "enabled": True,
        "targets": [{"id": 1, "name": "test", "kind": "chat"}],
        "text": "test",
        "interval_min": None,
        "interval_max": None,
        "time": time,
        "weekdays": [],
        "dates": [],
        "last_fired": None,
    }


class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.schedules_path = os.path.join(self.tmp.name, "schedules.json")
        self.queue_path = os.path.join(self.tmp.name, "queue.json")
        self.patches = [
            patch.object(web, "SCHEDULES_JSON", self.schedules_path),
            patch.object(web, "QUEUE_JSON", self.queue_path),
            patch.object(web, "get_user", lambda owner: {"id": owner, "status": "approved"}),
            patch.object(web, "_sub_active", lambda user: True),
            patch.object(
                web,
                "get_profile",
                lambda pid: {"id": pid, "owner": f"owner-{pid}", "active": True},
            ),
            patch.object(web, "_active_pid", lambda owner: owner.removeprefix("owner-")),
            patch.object(web, "_on_cooldown", lambda profile: False),
            patch.object(web.random, "randint", lambda lo, hi: lo),
        ]
        for item in self.patches:
            item.start()
        web.state.client_locks.clear()
        web.state.send_tasks.clear()
        web.state.send_jobs.clear()

    async def asyncTearDown(self):
        tasks = list(web.state.send_tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        web.state.send_tasks.clear()
        web.state.send_jobs.clear()
        web.state.client_locks.clear()
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    async def test_schedule_created_during_send_is_not_overwritten(self):
        web.save_schedules([interval_rule("slow", "p1")])
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow_fire(rule):
            # next_fire обязан быть на диске ещё до начала длительной отправки.
            stored = {r["id"]: r for r in web.load_schedules()}
            self.assertIsNotNone(stored[rule["id"]]["next_fire"])
            started.set()
            await release.wait()

        now = datetime(2026, 7, 29, 12, 0, 0)
        with patch.object(web, "_fire_rule_safe", slow_fire):
            web._scheduler_tick(now)
            await asyncio.wait_for(started.wait(), timeout=1)

            # Имитируем POST /schedules, пока первая рассылка ещё выполняется.
            rows = web.load_schedules()
            rows.append(interval_rule("new", "p2"))
            web.save_schedules(rows)

            release.set()
            await asyncio.gather(*list(web.state.send_tasks.values()))

        stored = {r["id"]: r for r in web.load_schedules()}
        self.assertEqual(set(stored), {"slow", "new"})
        self.assertIsNone(stored["new"]["next_fire"])

    async def test_due_rules_of_different_profiles_start_concurrently(self):
        web.save_schedules([
            interval_rule("a", "p1"),
            interval_rule("b", "p2"),
        ])
        both_started = asyncio.Event()
        release = asyncio.Event()
        started = []

        async def slow_fire(rule):
            started.append(rule["id"])
            if len(started) == 2:
                both_started.set()
            await release.wait()

        with patch.object(web, "_fire_rule_safe", slow_fire):
            web._scheduler_tick(datetime(2026, 7, 29, 12, 0, 0))
            await asyncio.wait_for(both_started.wait(), timeout=1)
            self.assertEqual(set(started), {"a", "b"})
            self.assertEqual(set(web.state.send_tasks), {"p1", "p2"})
            release.set()
            await asyncio.gather(*list(web.state.send_tasks.values()))

    async def test_one_profile_never_overlaps_and_oldest_rule_gets_next_slot(self):
        web.save_schedules([
            interval_rule("older", "p1", next_fire="2026-07-29T11:00:00"),
            interval_rule("new", "p1"),
        ])
        first_started = asyncio.Event()
        release_first = asyncio.Event()
        started = []

        async def fire(rule):
            started.append(rule["id"])
            if len(started) == 1:
                first_started.set()
                await release_first.wait()

        now = datetime(2026, 7, 29, 12, 0, 0)
        with patch.object(web, "_fire_rule_safe", fire):
            web._scheduler_tick(now)
            await asyncio.wait_for(first_started.wait(), timeout=1)
            self.assertEqual(started, ["older"])

            # Повторный тик во время отправки не запускает второй bulk.
            web._scheduler_tick(now)
            await asyncio.sleep(0)
            self.assertEqual(started, ["older"])

            release_first.set()
            await asyncio.gather(*list(web.state.send_tasks.values()))

            # У старого правила next_fire уже в будущем, новое получает слот.
            web._scheduler_tick(now)
            await asyncio.sleep(0)
            self.assertEqual(started, ["older", "new"])
            await asyncio.gather(*list(web.state.send_tasks.values()))

    async def test_busy_profile_keeps_overdue_marker_for_retry(self):
        old_fire = "2026-07-29T11:00:00"
        web.save_schedules([interval_rule("a", "p1", next_fire=old_fire)])
        release = asyncio.Event()

        async def manual_send():
            await release.wait()

        task = web._start_send_task("p1", manual_send)
        self.assertIsNotNone(task)
        web._scheduler_tick(datetime(2026, 7, 29, 12, 0, 0))

        stored = web.load_schedules()[0]
        self.assertEqual(stored["next_fire"], old_fire)
        release.set()
        await task

    async def test_daily_occurrence_is_saved_before_send_starts(self):
        web.save_schedules([daily_rule("daily", "p1")])
        observed = asyncio.Event()

        async def inspect_fire(_rule):
            self.assertEqual(web.load_schedules()[0]["last_fired"], "2026-07-29T12:00")
            observed.set()

        with patch.object(web, "_fire_rule_safe", inspect_fire):
            web._scheduler_tick(datetime(2026, 7, 29, 12, 2, 0))
            await asyncio.wait_for(observed.wait(), timeout=1)
            await asyncio.gather(*list(web.state.send_tasks.values()))

    async def test_second_clock_rule_survives_five_minute_window(self):
        web.save_schedules([
            daily_rule("first", "p1"),
            daily_rule("second", "p1"),
        ])
        first_started = asyncio.Event()
        release_first = asyncio.Event()
        started = []

        async def fire(rule):
            started.append(rule["id"])
            if len(started) == 1:
                first_started.set()
                await release_first.wait()

        with patch.object(web, "_fire_rule_safe", fire):
            web._scheduler_tick(datetime(2026, 7, 29, 12, 0, 0))
            await asyncio.wait_for(first_started.wait(), timeout=1)
            rows = {r["id"]: r for r in web.load_schedules()}
            self.assertEqual(rows["second"]["pending_fire"], "2026-07-29T12:00")

            release_first.set()
            await asyncio.gather(*list(web.state.send_tasks.values()))

            # Уже 12:06, когда обычное окно _due() закрыто, но pending не теряется.
            web._scheduler_tick(datetime(2026, 7, 29, 12, 6, 0))
            await asyncio.sleep(0)
            self.assertEqual(started, ["first", "second"])
            await asyncio.gather(*list(web.state.send_tasks.values()))

    async def test_one_time_pending_rule_survives_midnight(self):
        rule = daily_rule("once", "p1", time="23:58")
        rule["dates"] = ["2026-07-29"]
        web.save_schedules([rule])
        release = asyncio.Event()

        async def manual_send():
            await release.wait()

        blocker = web._start_send_task("p1", manual_send)
        self.assertIsNotNone(blocker)

        # Occurrence фиксируется, даже если профиль занят в момент отправки.
        web._scheduler_tick(datetime(2026, 7, 29, 23, 58, 0))
        stored = web.load_schedules()[0]
        self.assertEqual(stored["pending_fire"], "2026-07-29T23:58")

        release.set()
        await blocker

        started = []

        async def fire(claimed):
            started.append(claimed["id"])

        with patch.object(web, "_fire_rule_safe", fire):
            # После полуночи дата уже формально прошла, но pending occurrence
            # всё равно должен быть отправлен до очистки разового правила.
            web._scheduler_tick(datetime(2026, 7, 30, 0, 6, 0))
            await asyncio.gather(*list(web.state.send_tasks.values()))

        self.assertEqual(started, ["once"])
        stored = web.load_schedules()[0]
        self.assertEqual(stored["last_fired"], "2026-07-29T23:58")
        self.assertNotIn("pending_fire", stored)

        # Следующий проход очищает уже исполненную прошедшую дату.
        web._scheduler_tick(datetime(2026, 7, 30, 0, 6, 0))
        self.assertFalse(web.load_schedules()[0]["enabled"])

    async def test_resume_reserves_profile_before_scheduler_starts(self):
        web.save_schedules([interval_rule("due", "p1")])
        web._write_json(self.queue_path, {
            "jobs": [{
                "pid": "p1",
                "owner": "owner-p1",
                "text": "test",
                "remaining": [{"id": 1, "name": "test", "kind": "chat"}],
                "done": 0,
                "ok": 0,
                "failed": [],
                "source": "расписание",
                "label": "по интервалу",
            }],
        })
        resumed = asyncio.Event()
        release = asyncio.Event()

        async def slow_resume(*args, **kwargs):
            resumed.set()
            await release.wait()

        with patch.object(web, "_send_bulk_safe", slow_resume):
            await web._resume_queued_sends()
            await asyncio.wait_for(resumed.wait(), timeout=1)
            self.assertTrue(web._send_busy("p1"))

            # Due-правило не claim'ится поверх докатываемой очереди.
            web._scheduler_tick(datetime(2026, 7, 29, 12, 0, 0))
            self.assertIsNone(web.load_schedules()[0]["next_fire"])

            release.set()
            await asyncio.gather(*list(web.state.send_tasks.values()))

    async def test_bulk_queue_exists_before_first_telegram_await(self):
        entered_get_client = asyncio.Event()
        never = asyncio.Event()

        async def slow_get_client(pid):
            entered_get_client.set()
            await never.wait()

        with patch.object(web, "get_client", slow_get_client):
            task = web._start_send_task(
                "p1",
                lambda: web._send_bulk(
                    "p1",
                    [{"id": 1, "name": "test", "kind": "chat"}],
                    "test",
                    fresh=False,
                ),
            )
            await asyncio.wait_for(entered_get_client.wait(), timeout=1)
            jobs = web._queue_load()
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["pid"], "p1")
            self.assertEqual(len(jobs[0]["remaining"]), 1)

            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            self.assertFalse(web._send_busy("p1"))

    async def test_initial_queue_write_error_does_not_leave_profile_busy(self):
        with patch.object(web, "_queue_put", side_effect=OSError("disk full")):
            await web._send_bulk_safe(
                "p1",
                [{"id": 1, "name": "test", "kind": "chat"}],
                "test",
                fresh=False,
            )

        self.assertFalse(web.state.send_jobs["p1"]["running"])
        self.assertFalse(web._send_busy("p1"))

    async def test_clock_claim_rolls_back_when_initial_queue_write_fails(self):
        web.save_schedules([daily_rule("daily", "p1")])

        with patch.object(web, "_queue_put", side_effect=OSError("disk full")):
            web._scheduler_tick(datetime(2026, 7, 29, 12, 0, 0))
            await asyncio.gather(*list(web.state.send_tasks.values()))

        stored = web.load_schedules()[0]
        self.assertIsNone(stored["last_fired"])
        self.assertEqual(stored["pending_fire"], "2026-07-29T12:00")
        self.assertFalse(web._send_busy("p1"))

    async def test_interval_claim_rolls_back_when_initial_queue_write_fails(self):
        web.save_schedules([interval_rule("interval", "p1")])

        with patch.object(web, "_queue_put", side_effect=OSError("disk full")):
            web._scheduler_tick(datetime(2026, 7, 29, 12, 0, 0))
            await asyncio.gather(*list(web.state.send_tasks.values()))

        stored = web.load_schedules()[0]
        self.assertIsNone(stored["next_fire"])
        self.assertFalse(web._send_busy("p1"))

    async def test_transient_connection_error_keeps_tail_for_retry(self):
        async def broken_get_client(pid):
            raise ConnectionError("temporary")

        with patch.object(web, "get_client", broken_get_client):
            await web._send_bulk_safe(
                "p1",
                [{"id": 1, "name": "test", "kind": "chat"}],
                "test",
                fresh=False,
            )

        jobs = web._queue_load()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["pid"], "p1")
        self.assertEqual(len(jobs[0]["remaining"]), 1)
        self.assertFalse(web.state.send_jobs["p1"]["running"])
        self.assertEqual(web.state.send_jobs["p1"]["status"], "ошибка — повторю автоматически")
        self.assertTrue(web._send_busy("p1"))

    async def test_retry_tail_blocks_new_send_but_resume_can_take_reservation(self):
        async def broken_get_client(pid):
            raise ConnectionError("temporary")

        with patch.object(web, "get_client", broken_get_client):
            await web._send_bulk_safe(
                "p1",
                [{"id": 1, "name": "test", "kind": "chat"}],
                "test",
                fresh=False,
            )

        self.assertTrue(web._send_busy("p1"))
        never_started = web._start_send_task("p1", lambda: asyncio.sleep(0))
        self.assertIsNone(never_started)

        resumed = asyncio.Event()
        release = asyncio.Event()

        async def slow_resume(*args, **kwargs):
            web.state.send_jobs["p1"] = {"running": True, "retry_pending": False}
            resumed.set()
            await release.wait()

        with patch.object(web, "_send_bulk_safe", slow_resume):
            await web._resume_queued_sends()
            await asyncio.wait_for(resumed.wait(), timeout=1)
            self.assertTrue(web._send_busy("p1"))
            release.set()
            await asyncio.gather(*list(web.state.send_tasks.values()))

    async def test_stop_clears_pending_retry_before_it_can_resume(self):
        web.state.send_jobs["p1"] = {
            "running": False,
            "retry_pending": True,
            "cancel": False,
            "total": 1,
        }
        web._write_json(self.queue_path, {
            "jobs": [{
                "pid": "p1",
                "owner": "owner-p1",
                "text": "test",
                "remaining": [{"id": 1, "name": "test", "kind": "chat"}],
            }],
        })

        result = await web.send_stop("p1", user={"id": "owner-p1"})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(web._queue_load(), [])
        self.assertFalse(web.state.send_jobs["p1"]["retry_pending"])
        self.assertEqual(web.state.send_jobs["p1"]["status"], "остановлено")
        self.assertFalse(web._send_busy("p1"))

    async def test_stop_cancels_retry_task_reserved_but_not_started(self):
        web.state.send_jobs["p1"] = {
            "running": False,
            "retry_pending": True,
            "cancel": False,
            "total": 1,
        }
        web._write_json(self.queue_path, {
            "jobs": [{
                "pid": "p1",
                "owner": "owner-p1",
                "text": "old",
                "remaining": [{"id": 1, "name": "test", "kind": "chat"}],
            }],
        })
        resumed = []

        async def should_not_start(*args, **kwargs):
            resumed.append(True)

        with patch.object(web, "_send_bulk_safe", should_not_start):
            # _resume резервирует task, но текущая корутина ещё не отдала ей ход.
            await web._resume_queued_sends()
            self.assertIn("p1", web.state.send_tasks)
            result = await web.send_stop("p1", user={"id": "owner-p1"})
            await asyncio.sleep(0)

        self.assertEqual(result, {"ok": True})
        self.assertEqual(resumed, [])
        self.assertEqual(web._queue_load(), [])
        self.assertNotIn("p1", web.state.send_tasks)
        self.assertFalse(web._send_busy("p1"))

    async def test_discarded_inactive_retry_does_not_leave_busy_marker(self):
        web.state.send_jobs["p1"] = {
            "running": False,
            "retry_pending": True,
            "total": 1,
        }
        web._write_json(self.queue_path, {
            "jobs": [{
                "pid": "p1",
                "owner": "owner-p1",
                "text": "old",
                "remaining": [{"id": 1, "name": "test", "kind": "chat"}],
            }],
        })

        with patch.object(web, "_active_pid", lambda owner: "p2"):
            await web._resume_queued_sends()

        self.assertEqual(web._queue_load(), [])
        self.assertFalse(web.state.send_jobs["p1"]["retry_pending"])
        self.assertEqual(web.state.send_jobs["p1"]["status"], "аккаунт не активный")
        self.assertFalse(web._send_busy("p1"))

    async def test_manual_send_reserves_before_opening_telegram_session(self):
        entered_get_client = asyncio.Event()
        release_get_client = asyncio.Event()
        get_client_calls = 0

        class Client:
            async def is_user_authorized(self):
                return True

        async def slow_get_client(pid):
            nonlocal get_client_calls
            get_client_calls += 1
            entered_get_client.set()
            await release_get_client.wait()
            return Client()

        body = web.SendIn(
            targets=[web.Target(id=1, name="test", kind="chat")],
            text="test",
        )
        user = {"id": "owner-p1"}
        with (
            patch.object(web, "_owned_profile", lambda pid, user: {"id": pid, "owner": user["id"]}),
            patch.object(web, "get_client", slow_get_client),
            patch.object(web, "_send_one", AsyncMock(return_value=("ok", None))),
            patch.object(web, "_log_send_run"),
        ):
            first = asyncio.create_task(web.send_now("p1", body, user=user))
            await asyncio.wait_for(entered_get_client.wait(), timeout=1)

            second = await web.send_now("p1", body, user=user)
            self.assertEqual(second.status_code, 409)
            self.assertEqual(get_client_calls, 1)

            release_get_client.set()
            result = await first
            self.assertTrue(result["ok"])
            self.assertFalse(web._send_busy("p1"))

    async def test_get_client_serializes_session_initialization(self):
        entered_connect = asyncio.Event()
        release_connect = asyncio.Event()
        instances = []

        class Client:
            def __init__(self, *args, **kwargs):
                self.connected = False
                instances.append(self)

            def is_connected(self):
                return self.connected

            async def connect(self):
                entered_connect.set()
                await release_connect.wait()
                self.connected = True

        profile = {"id": "p1", "api_id": 1, "api_hash": "0" * 32}
        with (
            patch.object(web, "get_profile", lambda pid: profile),
            patch.object(web, "TelegramClient", Client),
            patch.object(web, "_register_response_listener"),
        ):
            first = asyncio.create_task(web.get_client("p1"))
            await asyncio.wait_for(entered_connect.wait(), timeout=1)
            second = asyncio.create_task(web.get_client("p1"))
            await asyncio.sleep(0)
            self.assertEqual(len(instances), 1)

            release_connect.set()
            one, two = await asyncio.gather(first, second)
            self.assertIs(one, two)
            self.assertEqual(len(instances), 1)

        web.state.clients.pop("p1", None)


if __name__ == "__main__":
    unittest.main()
