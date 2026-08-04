"""Вступление в чаты: что за отказ и стоит ли идти по списку дальше.

Ошибки Telethon разбираем по имени класса и тексту — так разбор переживает
обновление библиотеки. Главное здесь: беду с аккаунтом нельзя спутать с
проблемой одной ссылки, иначе бот продолжит долбиться и словит бан.
"""

import unittest

import web


def fake(name, message=""):
    """Ошибка Telethon без самой Telethon — важны имя класса и текст."""
    return type(name, (Exception,), {})(message)


class ClassifyJoinErrorTests(unittest.TestCase):
    def check(self, error, expected):
        category, detail = web._classify_join_error(error)
        self.assertEqual(category, expected, f"{type(error).__name__} → {detail}")
        self.assertTrue(detail, "у отказа должно быть человеческое объяснение")

    def test_account_problems_stop_the_whole_run(self):
        for name in ("UserDeactivatedBanError", "AuthKeyUnregisteredError",
                     "SessionRevokedError", "PhoneNumberBannedError"):
            self.check(fake(name), "dead")
        for name in ("PeerFloodError", "UserRestrictedError",
                     "UserBannedInChannelError"):
            self.check(fake(name), "spam")
        self.check(fake("ChannelsTooMuchError"), "limit")

    def test_every_stopping_category_is_marked_as_stopping(self):
        for name in ("UserDeactivatedBanError", "PeerFloodError",
                     "ChannelsTooMuchError"):
            category, _ = web._classify_join_error(fake(name))
            self.assertIn(category, web._JOIN_STOP_CATEGORIES)

    def test_chat_asking_for_a_human_is_not_a_failure(self):
        # Заявка на вступление: её одобряет админ, ссылка исправна.
        self.check(fake("InviteRequestSentError",
                        "You have successfully requested to join this chat"), "request")
        self.check(fake("ChatAdminRequiredError"), "verify")
        self.check(fake("ChatGuestSendForbiddenError"), "verify")

    def test_full_chat_does_not_look_like_an_account_limit(self):
        # UsersTooMuchError — переполнен чат; ChannelsTooMuchError — аккаунт.
        self.check(fake("UsersTooMuchError"), "full")
        self.assertNotIn(
            web._classify_join_error(fake("UsersTooMuchError"))[0],
            web._JOIN_STOP_CATEGORIES,
        )

    def test_link_problems(self):
        self.check(fake("UserAlreadyParticipantError"), "already")
        self.check(fake("InviteHashExpiredError"), "expired")
        self.check(fake("InviteHashInvalidError"), "expired")
        self.check(fake("InviteHashEmptyError"), "expired")
        self.check(fake("ChannelPrivateError"), "skip")

    def test_unknown_error_is_reported_as_is(self):
        category, detail = web._classify_join_error(fake("WeirdNewError", "что-то новое"))
        self.assertEqual(category, "error")
        self.assertIn("что-то новое", detail)
        self.assertNotIn(category, web._JOIN_STOP_CATEGORIES)


class JoinMuteReasonTests(unittest.IsolatedAsyncioTestCase):
    class Chat:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    async def call(self, entity, participant=None, raises=False):
        class Client:
            async def __call__(self, request):
                if raises:
                    raise RuntimeError("обычная группа так не умеет")
                return JoinMuteReasonTests.Chat(participant=participant)
        return await web._join_mute_reason(Client(), entity)

    async def test_channel_is_not_expected_to_let_us_write(self):
        chat = self.Chat(broadcast=True,
                         default_banned_rights=self.Chat(send_messages=True))
        self.assertIsNone(await self.call(chat))

    async def test_chat_that_mutes_newcomers_needs_a_human(self):
        chat = self.Chat(broadcast=False,
                         default_banned_rights=self.Chat(send_messages=True))
        self.assertIsNotNone(await self.call(chat))

    async def test_personal_mute_by_a_captcha_bot_is_caught(self):
        chat = self.Chat(broadcast=False, default_banned_rights=None)
        muted = self.Chat(banned_rights=self.Chat(send_messages=True))
        self.assertIsNotNone(await self.call(chat, participant=muted))

    async def test_normal_chat_passes(self):
        chat = self.Chat(broadcast=False, default_banned_rights=None)
        free = self.Chat(banned_rights=None)
        self.assertIsNone(await self.call(chat, participant=free))

    async def test_unsupported_request_does_not_break_the_join(self):
        chat = self.Chat(broadcast=False, default_banned_rights=None)
        self.assertIsNone(await self.call(chat, raises=True))


class HumanLeftTests(unittest.TestCase):
    """Ожидание показываем словами: «1246с» владельцу ничего не говорит."""

    def test_time_reads_like_a_human_wrote_it(self):
        cases = {
            0: "0 сек", 45: "45 сек", 59: "59 сек",
            60: "1 мин", 90: "1 мин 30 сек", 1246: "20 мин 46 сек",
            3600: "1 ч", 3900: "1 ч 5 мин", 7325: "2 ч 2 мин",
        }
        for seconds, expected in cases.items():
            self.assertEqual(web._human_left(seconds), expected, seconds)

    def test_junk_does_not_break_the_message(self):
        self.assertEqual(web._human_left(-5), "0 сек")
        self.assertEqual(web._human_left(None), "")
        self.assertEqual(web._human_left("не число"), "")


if __name__ == "__main__":
    unittest.main()
