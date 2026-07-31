import json
import unittest

from payment_audit import analyze_payment_signal


class PaymentAuditTests(unittest.TestCase):
    def test_completed_sbp_transfer_with_amount_and_receipt_is_high_confidence(self):
        result = analyze_payment_signal(
            "Скинул 2 500 ₽ по СБП, чек прикрепил",
            direction="incoming",
            media_type="image/jpeg",
        )

        self.assertTrue(result["detected"])
        self.assertTrue(result["success_claim"])
        self.assertEqual(result["event_status"], "completed")
        self.assertEqual(result["level"], "high")
        self.assertEqual(result["direction"], "incoming")
        self.assertEqual(result["media_type"], "image")
        self.assertIn("transfer_completed", result["categories"])
        self.assertIn("payment_method", result["categories"])
        self.assertIn("receipt", result["categories"])
        self.assertEqual(
            result["amounts"],
            [{"value": 2500, "currency": "RUB", "raw": "2 500 ₽", "currency_explicit": True}],
        )

    def test_confirmation_of_receipt_is_distinct_from_sender_claim(self):
        result = analyze_payment_signal(
            "Перевод поступил, получила 1500 рублей",
            direction="outgoing",
        )

        self.assertTrue(result["success_claim"])
        self.assertEqual(result["event_status"], "completed")
        self.assertIn("payment_confirmation", result["categories"])
        self.assertNotIn("transfer_completed", result["categories"])
        self.assertEqual(result["amounts"][0]["value"], 1500)
        self.assertEqual(result["amounts"][0]["currency"], "RUB")

    def test_single_words_and_non_payment_uses_do_not_trigger(self):
        examples = (
            "скинул",
            "карта",
            "беру",
            "чек",
            "отправил",
            "Скинул фотографии в общий чат",
            "Беру зонт и выхожу",
            "Отправила документы менеджеру",
        )

        for message in examples:
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertFalse(result["detected"])
                self.assertFalse(result["success_claim"])
                self.assertEqual(result["level"], "none")

    def test_future_intent_is_not_a_completed_payment(self):
        result = analyze_payment_signal("Скину вечером 3 000 рублей за доступ")

        self.assertTrue(result["detected"])
        self.assertFalse(result["success_claim"])
        self.assertEqual(result["event_status"], "intent")
        self.assertIn("payment_intent", result["categories"])
        self.assertNotIn("transfer_completed", result["categories"])

    def test_purchase_language_is_a_review_signal_but_not_payment_proof(self):
        result = analyze_payment_signal("Покупаю, беру встречу за 7000 руб")

        self.assertTrue(result["detected"])
        self.assertFalse(result["success_claim"])
        self.assertEqual(result["event_status"], "intent")
        self.assertIn("purchase_intent", result["categories"])
        self.assertEqual(result["amounts"][0]["value"], 7000)

    def test_request_for_bank_details_is_detected(self):
        result = analyze_payment_signal("Пришли реквизиты карты, переведу по СБП")

        self.assertTrue(result["detected"])
        self.assertFalse(result["success_claim"])
        self.assertEqual(result["event_status"], "requested")
        self.assertIn("payment_request", result["categories"])
        self.assertIn("payment_method", result["categories"])
        self.assertIn("payment_intent", result["categories"])

    def test_direct_request_for_money_is_detected_but_request_for_photo_is_not(self):
        payment = analyze_payment_signal("Скинь мне 2500 на карту")
        photo = analyze_payment_signal("Скинь мне фото с прогулки")

        self.assertTrue(payment["detected"])
        self.assertEqual(payment["event_status"], "requested")
        self.assertFalse(payment["success_claim"])
        self.assertFalse(photo["detected"])

    def test_failed_transfer_is_negated_and_never_successful(self):
        result = analyze_payment_signal("Не скинул 3000 ₽ — перевод не прошел")

        self.assertTrue(result["detected"])
        self.assertTrue(result["negated"])
        self.assertFalse(result["success_claim"])
        self.assertEqual(result["event_status"], "failed_or_reversed")
        self.assertIn("payment_negation", result["categories"])
        self.assertTrue(result["negation_reasons"])

    def test_refund_is_not_counted_as_income(self):
        result = analyze_payment_signal("Вернула деньги, возврат перевода 5000 рублей")

        self.assertTrue(result["detected"])
        self.assertTrue(result["negated"])
        self.assertFalse(result["success_claim"])
        self.assertIn("refund_or_reversal", result["categories"])

    def test_negative_non_payment_action_does_not_trigger(self):
        result = analyze_payment_signal("Не отправил документы, потому что забыл")

        self.assertFalse(result["detected"])
        self.assertFalse(result["success_claim"])

    def test_forward_and_quote_are_not_attributed_to_current_sender(self):
        direct = analyze_payment_signal("Скинул 5000 рублей за заказ")
        forwarded = analyze_payment_signal(
            "Скинул 5000 рублей за заказ",
            is_forwarded=True,
        )
        quoted = analyze_payment_signal(
            "Скинул 5000 рублей за заказ",
            is_quote=True,
        )

        self.assertTrue(direct["success_claim"])
        self.assertFalse(forwarded["success_claim"])
        self.assertFalse(quoted["success_claim"])
        self.assertFalse(forwarded["attributable"])
        self.assertEqual(forwarded["attribution"], "forwarded")
        self.assertLess(forwarded["confidence"], direct["confidence"])
        self.assertLess(quoted["confidence"], direct["confidence"])

    def test_caption_and_media_metadata_are_supported(self):
        result = analyze_payment_signal(
            caption="Вот чек перевода на 4 500 рублей",
            media_metadata={"mime_type": "image/png", "forwarded": False},
        )

        self.assertTrue(result["detected"])
        self.assertEqual(result["event_status"], "receipt")
        self.assertEqual(result["media_type"], "image")
        self.assertEqual(result["amounts"][0]["value"], 4500)

    def test_short_receipt_caption_only_works_with_document_metadata(self):
        text_only = analyze_payment_signal("чек")
        image_caption = analyze_payment_signal(caption="чек", media_type="photo")

        self.assertFalse(text_only["detected"])
        self.assertTrue(image_caption["detected"])
        self.assertEqual(image_caption["level"], "low")
        self.assertEqual(image_caption["event_status"], "receipt")

    def test_amount_formats_and_json_serialisation(self):
        result = analyze_payment_signal("Оплатил $100, 1.500 ₽ и еще 15 тыс. руб за услуги")

        self.assertEqual(
            [(item["value"], item["currency"]) for item in result["amounts"]],
            [(100, "USD"), (1500, "RUB"), (15000, "RUB")],
        )
        json.dumps(result, ensure_ascii=False)

    def test_dates_and_times_are_not_mistaken_for_bare_amounts(self):
        result = analyze_payment_signal("Переведу завтра в 15:30, заказ от 29.07")

        self.assertTrue(result["detected"])
        self.assertEqual(result["amounts"], [])

    def test_cards_phones_accounts_and_order_ids_are_not_amounts(self):
        examples = (
            "Скинул на карту 2200 7012 3456 7890",
            "Переведи по номеру телефона +7 999 123-45-67",
            "Перевел деньги на счет 40817810099910004312",
            "Оплатил заказ №123456",
            "Оплатил order id 987654",
            "Скинул на карту **** 7890",
            "Телефон: последние 4 цифры 4567, переведи деньги",
            "Код операции 654321, перевод выполнен",
            "Скинул на карту 2200•7012•3456•7890",
            "Скинул на карту 2200.7012.3456.7890",
            "Оплатил счет 4081/7810/0999/1000/4312",
            "Скинул по номеру телефона +7•999•123•45•67",
        )

        for message in examples:
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertTrue(result["detected"])
                self.assertEqual(result["amounts"], [])

    def test_real_amount_next_to_order_id_is_preserved(self):
        result = analyze_payment_signal(
            "Номер заказа 123456, оплатил 5000 рублей"
        )

        self.assertTrue(result["detected"])
        self.assertEqual(
            [(item["value"], item["currency"]) for item in result["amounts"]],
            [(5000, "RUB")],
        )

    def test_quantities_sent_as_content_are_not_payment_amounts(self):
        examples = (
            "Отправил 30 фотографий клиенту",
            "Отправь мне 30 фотографий",
            "Скину 20 файлов вечером",
            "Внес 25 изменений в документ",
            "Перевел 30 предложений для заказа",
            "Отправил 5000 просмотров",
            "Отправил 5000 подписчиков",
            "Отправил 5000 баллов",
            "Отправил 5000 заявок",
            "Отправил 5000 лидов",
            "Отправил 5000 лайков",
            "Отправил 5000 фоток",
            "Отправил 5к фото",
            "Получил 5000 подписчиков",
            "Получил 5000 заявок",
        )

        for message in examples:
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertFalse(result["detected"])
                self.assertFalse(result["success_claim"])
                self.assertEqual(result["amounts"], [])

    def test_quantity_and_real_payment_amount_are_separated(self):
        result = analyze_payment_signal(
            "Отправил 5000 рублей за 30 фото"
        )

        self.assertTrue(result["detected"])
        self.assertTrue(result["success_claim"])
        self.assertEqual([item["value"] for item in result["amounts"]], [5000])

    def test_broad_negations_remove_positive_payment_categories(self):
        examples = (
            "Не поступило 5000 рублей",
            "Не пришло 5000 ₽",
            "Перевод не выполнен, сумма 5000 ₽",
            "Не скину 5000 рублей",
            "Не переведу 3000 рублей",
            "Не покупаю, цена 5000 рублей",
            "Не беру встречу за 7000 рублей",
        )
        positive_categories = {
            "transfer_completed",
            "payment_confirmation",
            "payment_intent",
            "purchase_intent",
        }

        for message in examples:
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertTrue(result["detected"])
                self.assertTrue(result["negated"])
                self.assertFalse(result["success_claim"])
                self.assertEqual(result["event_status"], "failed_or_reversed")
                self.assertIn("payment_negation", result["categories"])
                self.assertTrue(positive_categories.isdisjoint(result["categories"]))

    def test_not_only_phrase_is_not_treated_as_negation(self):
        result = analyze_payment_signal(
            "Не только перевел 5000 рублей, но и прислал чек"
        )

        self.assertTrue(result["detected"])
        self.assertFalse(result["negated"])
        self.assertTrue(result["success_claim"])

    def test_generic_file_actions_need_real_payment_context(self):
        non_payments = (
            "Отправил документ по заказу №12345",
            "Перевел текст для заказа 12345",
            "Закинул 5 постов в рабочий чат",
        )
        for message in non_payments:
            with self.subTest(message=message):
                self.assertFalse(analyze_payment_signal(message)["detected"])

        payment = analyze_payment_signal("Отправил 5000 рублей за заказ")
        self.assertTrue(payment["detected"])
        self.assertTrue(payment["success_claim"])

    def test_questions_and_uncertainty_are_never_success_claims(self):
        examples = (
            "Получил 5000?",
            "Деньги пришли?",
            "Не уверен, перевод поступил",
            "Возможно перевод поступил",
        )

        for message in examples:
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertTrue(result["detected"])
                self.assertTrue(result["uncertain"])
                self.assertFalse(result["success_claim"])
                self.assertEqual(result["event_status"], "uncertain")
                self.assertIn(result["level"], {"low", "medium"})
                self.assertLessEqual(result["confidence"], 0.58)

    def test_short_nominal_payment_requests_are_review_signals(self):
        for message in (
            "Оплата 5000",
            "Перевод 5000",
            "Предоплата 5000",
            "Аванс 5000",
            "Задаток 5000",
        ):
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertTrue(result["detected"])
                self.assertFalse(result["success_claim"])
                self.assertEqual(result["event_status"], "requested")
                self.assertIn("payment_request", result["categories"])
                self.assertEqual(result["amounts"][0]["value"], 5000)

    def test_future_payment_and_commerce_object_phrases_are_low_intent(self):
        for message in (
            "Заплачу завтра",
            "Оплачу завтра",
            "Беру заказ",
            "Покупаю услугу",
            "Бронирую встречу",
        ):
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertTrue(result["detected"])
                self.assertFalse(result["success_claim"])
                self.assertEqual(result["event_status"], "intent")
                self.assertEqual(result["level"], "low")

    def test_participles_and_reversed_confirmation_order_are_supported(self):
        for message in (
            "Заказ оплачен",
            "Получена оплата",
            "Поступили деньги",
            "Пришла оплата",
        ):
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertTrue(result["detected"])
                self.assertTrue(result["success_claim"])
                self.assertEqual(result["event_status"], "completed")

    def test_reversal_word_order_and_colloquial_refunds_are_not_successes(self):
        for message in (
            "Перевод вернули",
            "Деньги вернулись",
            "Оплату отменили",
            "Скинула назад 5000",
            "Скинула обратно 5000",
            "Сделала возврат 5000",
            "Возврат 5000",
            "Вернул 5000",
        ):
            with self.subTest(message=message):
                result = analyze_payment_signal(message)
                self.assertTrue(result["detected"])
                self.assertTrue(result["negated"])
                self.assertFalse(result["success_claim"])
                self.assertEqual(result["event_status"], "failed_or_reversed")
                self.assertIn("refund_or_reversal", result["categories"])

    def test_generic_completed_claim_is_capped_at_medium_confidence(self):
        result = analyze_payment_signal("Скинул 5000")

        self.assertTrue(result["detected"])
        self.assertTrue(result["success_claim"])
        self.assertEqual(result["level"], "medium")
        self.assertLessEqual(result["confidence"], 0.61)


if __name__ == "__main__":
    unittest.main()


class MoneyTraceCaptureTests(unittest.TestCase):
    """Рабочие чаты часто удаляют после заказа — денежный след теряться не должен."""

    def trace(self, text, direction="incoming"):
        result = analyze_payment_signal(text, direction=direction)
        return bool(result["detected"] or result["money_mentioned"])

    def test_keeps_words_the_owner_named(self):
        for text in (
            "скинул 5000 на карту",
            "перевел 3000",
            "закинул на карту",
            "отправил, проверяй",
            "скинул, проверь",
            "деньги есть",
            "оплата есть",
        ):
            with self.subTest(text=text):
                self.assertTrue(self.trace(text))

    def test_keeps_money_talk_that_is_not_a_proof(self):
        for text in (
            "перевод не прошёл",
            "не смогла перевести, попробую позже",
            "верну 5000 завтра",
            "куда кидать",
            "какая карта?",
            "жду оплату",
            "по 2500 за штуку, итого 10000",
        ):
            with self.subTest(text=text):
                self.assertTrue(self.trace(text))

    def test_still_ignores_messages_that_are_not_about_money(self):
        for text in (
            "скинул фотки с объекта",
            "5000 просмотров за сутки",
            "проверь почту",
            "отправил документы на почту",
            "привет, как дела",
            "завтра встречаемся в 10",
            "отправь на 2202 2020 1234 5678",
        ):
            with self.subTest(text=text):
                self.assertFalse(self.trace(text))

    def test_weak_trace_carries_its_own_evidence(self):
        result = analyze_payment_signal("скинул, проверяй", direction="incoming")
        self.assertFalse(result["detected"])
        self.assertTrue(result["money_mentioned"])
        self.assertTrue(result["money_evidence"], "у слабого следа должна быть улика")

    def test_verify_word_alone_is_not_money(self):
        result = analyze_payment_signal("проверь почту пожалуйста", direction="incoming")
        self.assertFalse(result["money_mentioned"])
