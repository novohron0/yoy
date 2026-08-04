"""Расчётная неделя сотрудника: от какого рубежа считать «должно быть выплачено».

Период привязан к концу подписки (``paid_until``) и всегда закрывается в
прошлом — платим только за неделю, которая уже прошла.
"""

import unittest
from datetime import datetime, timedelta, timezone

import web


WEEK = timedelta(days=7)
# Границы периода пишутся с точностью до секунды — сравниваем без микросекунд.
NOW = datetime.now().replace(microsecond=0)


def parse(value):
    return datetime.fromisoformat(value)


class PayoutPeriodTests(unittest.TestCase):
    def test_expired_subscription_closes_the_week_on_its_end(self):
        paid_until = NOW - timedelta(days=2)
        start, end = web._payout_period({"paid_until": paid_until.isoformat()})
        self.assertEqual(parse(end), paid_until.astimezone(timezone.utc))
        self.assertEqual(parse(end) - parse(start), WEEK)

    def test_active_subscription_uses_the_week_that_already_passed(self):
        paid_until = NOW + timedelta(days=3)
        start, end = web._payout_period({"paid_until": paid_until.isoformat()})
        # Неделя вперёд ещё не отработана: рубеж отступает на 7 дней назад.
        self.assertEqual(parse(end), (paid_until - WEEK).astimezone(timezone.utc))
        self.assertLess(parse(end), datetime.now(timezone.utc))
        self.assertEqual(parse(end) - parse(start), WEEK)

    def test_long_subscription_walks_back_to_the_last_passed_boundary(self):
        paid_until = NOW + timedelta(days=25)
        start, end = web._payout_period({"paid_until": paid_until.isoformat()})
        self.assertEqual(parse(end), (paid_until - 4 * WEEK).astimezone(timezone.utc))
        self.assertLess(parse(end), datetime.now(timezone.utc))
        self.assertEqual(parse(end) - parse(start), WEEK)

    def test_without_a_subscription_the_week_is_closed_right_now(self):
        start, end = web._payout_period({})
        self.assertLessEqual(
            abs((parse(end) - datetime.now(timezone.utc)).total_seconds()), 5
        )
        self.assertEqual(parse(end) - parse(start), WEEK)

    def test_broken_paid_until_does_not_break_the_period(self):
        start, end = web._payout_period({"paid_until": "не дата"})
        self.assertLessEqual(
            abs((parse(end) - datetime.now(timezone.utc)).total_seconds()), 5
        )
        self.assertEqual(parse(end) - parse(start), WEEK)

    def test_next_period_starts_where_the_paid_one_ended(self):
        paid_until = NOW - timedelta(days=1)
        _, end = web._payout_period({"paid_until": paid_until.isoformat()})
        last_end = (parse(end) - timedelta(days=3)).isoformat(timespec="seconds")
        start, again = web._payout_period(
            {"paid_until": paid_until.isoformat()}, last_end
        )
        self.assertEqual(again, end)
        self.assertEqual(parse(start), parse(last_end))

    def test_stale_last_end_falls_back_to_a_full_week(self):
        paid_until = NOW - timedelta(days=1)
        _, end = web._payout_period({"paid_until": paid_until.isoformat()})
        # Прошлый период кончился позже нового рубежа — берём обычные 7 дней.
        last_end = (parse(end) + timedelta(days=2)).isoformat(timespec="seconds")
        start, again = web._payout_period(
            {"paid_until": paid_until.isoformat()}, last_end
        )
        self.assertEqual(again, end)
        self.assertEqual(parse(again) - parse(start), WEEK)


if __name__ == "__main__":
    unittest.main()
