"""Heuristic signals for consent-based payment reconciliation.

The detector deliberately does *not* claim that a bank transfer is genuine.  It
turns message text/captions and a small amount of message metadata into a
JSON-serialisable review signal.  A real payment must still be reconciled with
a bank statement, payment-provider webhook, or a human reviewer.

Only the returned evidence fragments need to be stored.  Callers do not need to
persist the original message body in order to show why a signal was raised.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

__all__ = ["analyze_payment_signal", "analyze_message"]


_SPACE_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[a-zа-я0-9₽$€]+", re.IGNORECASE)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# A completed-action verb alone is intentionally insufficient.  For example,
# «скинул фотографии» must not become a transfer signal.  The contextual gate
# below also requires money, an amount, a payment method, or a commerce object.
_COMPLETED_RE = _rx(
    r"\b(?:"
    r"перевел(?:а|и)?|перекинул(?:а|и)?|"
    r"скинул(?:а|и)?|кинул(?:а|и)?|отправил(?:а|и)?|закинул(?:а|и)?|"
    r"оплатил(?:а|и)?|заплатил(?:а|и)?|"
    r"внес(?:ла|ли)?|зачислил(?:а|и)?"
    r")\b|\b(?:оплачен(?:а|о|ы)?|заплачен(?:а|о|ы)?|отправлено|переведено)\b|"
    r"\b(?:оплата|платеж|перевод)\s+(?:успешно\s+)?прош(?:ел|ла)\b"
    r"|\bперевод\s+(?:успешно\s+)?выполнен\b"
)

# These verbs are also routinely used for files, photographs, documents and
# other non-money objects.  They need stronger context than «оплатил» or an
# explicit bank-transfer phrase.
_GENERIC_COMPLETED_RE = _rx(
    r"\b(?:скинул(?:а|и)?|кинул(?:а|и)?|отправил(?:а|и)?|"
    r"закинул(?:а|и)?|отправлено)\b"
)

_INHERENT_PAYMENT_COMPLETED_RE = _rx(
    r"\b(?:оплатил(?:а|и)?|заплатил(?:а|и)?|"
    r"оплачен(?:а|о|ы)?|заплачен(?:а|о|ы)?)\b|"
    r"\b(?:оплата|платеж|перевод)\s+(?:успешно\s+)?прош(?:ел|ла)\b|"
    r"\bперевод\s+(?:успешно\s+)?выполнен\b"
)

_INTENT_RE = _rx(
    r"\b(?:"
    r"переведу|перевожу|перекину|"
    r"скину|кину|отправлю|закину|"
    r"оплачу|оплачиваю|заплачу|внесу"
    r")\b"
)

_GENERIC_INTENT_RE = _rx(r"\b(?:скину|кину|отправлю|закину)\b")

_INHERENT_PAYMENT_INTENT_RE = _rx(
    r"\b(?:оплачу|оплачиваю|заплачу)\b"
)

_PURCHASE_RE = _rx(
    r"\b(?:покупаю|куплю|беру|забираю|бронирую|оформляю)\b"
)

_WORK_OBJECT_RE = _rx(
    r"\b(?:заказ[а-я]*|услуг[а-я]*|доступ[а-я]*|встреч[а-я]*|"
    r"брон[а-я]*|недел[а-я]*|мест[а-я]*|смен[а-я]*|работ[а-я]*|"
    r"заявк[а-я]*|тариф[а-я]*|подписк[а-я]*|консультаци[а-я]*|"
    r"размещени[а-я]*)\b"
)

_REQUEST_PATTERNS = (
    _rx(
        r"\b(?:оплата|перевод|предоплата|аванс|задаток)\s*"
        r"(?:[:—–-]\s*)?(?:[$€₽]\s*)?\d"
    ),
    _rx(
        r"\b(?:скинь|скиньте|переведи|переведите|отправь|отправьте|"
        r"закинь|закиньте|оплати|оплатите)\s+(?:мне\s+)?"
        r"(?:\d|деньги|оплату|перевод|на\s+карту)"
    ),
    _rx(
        r"\b(?:можешь|можете|сможешь|сможете)\s+"
        r"(?:скинуть|перевести|отправить|закинуть|оплатить)\s+"
        r"(?:мне\s+)?(?:\d|деньги|оплату|перевод|на\s+карту)"
    ),
    _rx(
        r"\b(?:скинь|скиньте|переведи|переведите|отправь|отправьте|"
        r"закинь|закиньте)\s+(?:мне\s+)?"
        r"(?:по\s+номер(?:у|а)\s+(?:телефона|карты)|на\s+карту|через\s+сбп)\b"
    ),
    _rx(
        r"\b(?:скинь|скиньте|пришли|пришлите|дай|дайте|напиши|напишите)"
        r"\s+(?:мне\s+)?(?:свои\s+)?(?:банковские\s+)?"
        r"(?:реквизиты|номер\s+карты|номер\s+телефона)\b"
    ),
    _rx(
        r"\bкуда\s+(?:тебе|вам|можно\s+)?"
        r"(?:скинуть|скидывать|перевести|переводить|отправить|отправлять|"
        r"оплатить|оплачивать|закинуть|закидывать|кидать|кинуть)\b"
    ),
    # «какая карта?», «карта какая», «на какую карту» — спрашивают реквизиты
    _rx(r"\b(?:как(?:ая|ой|ую)\s+(?:у\s+тебя\s+|у\s+вас\s+)?(?:карта|карту|банк|сбер|тинькоф+)|"
        r"карта\s+как(?:ая|ой)|на\s+как(?:ую|ой)\s+(?:карту|номер|банк))\b"),
    _rx(r"\bномер\s+карты\s*\?"),
    _rx(r"\b(?:жду|нужны)\s+(?:твои|ваши|банковские\s+)?реквизиты\b"),
    _rx(r"\b(?:выставь|выставите|пришли|пришлите)\s+(?:мне\s+)?счет\b"),
)

_METHOD_PATTERNS = (
    _rx(r"\bсбп\b"),
    _rx(r"\b(?:на|с)\s+(?:банковскую\s+)?карт(?:у|ы)\b"),
    _rx(r"\bпо\s+номер(?:у|а)\s+(?:телефона|карты)\b"),
    _rx(r"\bбанковск(?:ий|им|ого)\s+перевод(?:ом|а)?\b"),
    _rx(r"\b(?:реквизиты|номер\s+карты)\b"),
)

_TRANSFER_DESTINATION_RE = _rx(
    r"\b(?:сбп|на\s+(?:банковскую\s+)?карту|"
    r"по\s+номер(?:у|а)\s+(?:телефона|карты)|банковск(?:ий|им)\s+перевод(?:ом)?)\b"
)

_RECEIPT_PATTERNS = (
    _rx(r"\bчек\s+(?:об\s+)?(?:оплат[ые]|перевод[ае]?|платеж[ае]?)\b"),
    _rx(r"\b(?:скрин|скриншот|фото)\s+(?:чека|оплаты|перевода|платежа)\b"),
    _rx(r"\b(?:квитанци[яюи]|платежное\s+поручение)\b"),
    _rx(r"\b(?:вот|держи|прикрепил(?:а)?|отправил(?:а)?)\s+чек\b"),
)

_RECEIPT_WORD_RE = _rx(r"\b(?:чек|квитанция)\b")

_CONFIRMATION_PATTERNS = (
    _rx(
        r"\b(?:деньги|перевод|оплата|платеж)\s+"
        r"(?:уже\s+)?(?:пришл[аи]|пришел|дошл[аи]|дошел|поступил[аи]?|зачислен[аы]?)\b"
    ),
    _rx(
        r"\b(?:получил|получила|получили)\s+"
        r"(?:деньги|оплату|перевод|платеж|\d)"
    ),
    _rx(r"\b(?:вижу|подтверждаю)\s+(?:твою\s+|вашу\s+)?(?:оплату|перевод|платеж)\b"),
    _rx(r"\b(?:оплата|перевод|платеж)\s+(?:получен[ао]?|зачислен[ао]?)\b"),
    _rx(
        r"\b(?:получен[аоы]?|поступил[аи]?|пришл[аи]|пришел|"
        r"зачислен[аоы]?)\s+(?:оплата|перевод|платеж|деньги)\b"
    ),
    _rx(r"\bесть\s+(?:оплата|перевод|поступление|деньги)\b"),
    _rx(r"\b(?:оплата|перевод|платеж|деньги)\s+есть\b"),
    _rx(r"\b(?:пришло|поступило|зачислено)\s+\d"),
    # «всё получила», «всё пришло», «деньги упали» — подтверждение получения
    _rx(r"\bвс[её]\s+(?:получил(?:а|и)?|пришло|дошло|на\s+месте)\b"),
    _rx(r"\b(?:деньги|оплата|перевод|платеж)\s+(?:упал[аои]?|прилетел[аои]?)\b"),
)

# «скинул, проверяй» — просьба посмотреть поступление. Само по себе слово ничего
# не значит («проверь почту»), поэтому засчитывается только рядом с деньгами.
_VERIFY_PATTERNS = (
    _rx(
        r"\b(?:проверь(?:те)?|проверяй(?:те)?|глянь(?:те)?|посмотри(?:те)?|"
        r"чекни(?:те)?)\s+(?:пожалуйста\s+)?(?:там\s+)?"
        r"(?:карт[уы]|сч[ёе]т|баланс|оплату|перевод|платеж|деньги|поступление)\b"
    ),
    _rx(r"\b(?:проверь(?:те)?|проверяй(?:те)?|глянь(?:те)?|чекни(?:те)?)\b"),
)

# Слова, которые сами по себе не доказывают перевод, но означают, что о деньгах
# в этом чате говорили. Влияют ТОЛЬКО на «сохранить слабый след» — в оценку
# уверенности и в признак отрицания не входят, чтобы не портить основной разбор.
_MONEY_TALK_PATTERNS = (
    _rx(r"\b(?:верн(?:у|[ёе]м|ут)|возвращ(?:у|ает)|возврат[а-я]*)\b"),
    _rx(r"\b(?:итого|цена|ценник|стоимость|прайс|стоит)\b"),
    _rx(r"\b(?:жду|ждем|жд[ёе]м)\s+(?:оплат[а-я]*|перевод[а-я]*|деньги)\b"),
)

_UNCERTAINTY_PATTERNS = (
    _rx(
        r"\b(?:не\s+уверен(?:а|ы)?|возможно|может\s+быть|кажется|"
        r"наверное|похоже|вроде)\b"
    ),
)

_QUESTION_MARK_RE = _rx(r"\?")

_PAYMENT_CONTEXT_RE = _rx(
    r"\b(?:"
    r"деньги|оплат[а-я]*|предоплат[а-я]*|платеж[а-я]*|перевод[а-я]*|"
    r"сбп|реквизит[а-я]*|счет|чек|квитанци[а-я]*|"
    r"заказ[а-я]*|услуг[а-я]*|доступ[а-я]*|брон[а-я]*|"
    r"встреч[а-я]*|недел[а-я]*|работ[а-я]*"
    r")\b"
)

_MONEY_CONTEXT_RE = _rx(
    r"\b(?:деньги|оплат[а-я]*|предоплат[а-я]*|платеж[а-я]*|"
    r"перевод[а-я]*|аванс[а-я]*|задаток[а-я]*|сбп)\b"
)

_NEGATION_PATTERNS = (
    _rx(
        r"\bне\s+(?!только\b)(?:смог(?:ла|ли)?\s+)?(?:"
        r"перевести|перевел(?:а|и)?|перекинуть|перекинул(?:а|и)?|"
        r"скинуть|скинул(?:а|и)?|отправить|отправил(?:а|и)?|"
        r"закинуть|закинул(?:а|и)?|оплатить|оплатил(?:а|и)?|"
        r"заплатить|заплатил(?:а|и)?|получил(?:а|и)?|"
        r"переведу|перевожу|перекину|скину|кину|отправлю|закину|"
        r"оплачу|оплачиваю|заплачу|внесу|"
        r"покупаю|куплю|беру|забираю|бронирую|оформляю|"
        r"переводи|перекидывай|скидывай|отправляй|закидывай|"
        r"оплачивай|покупай|бери|"
        r"оплачен(?:а|о|ы)?|заплачен(?:а|о|ы)?|отправлено|переведено"
        r")\b"
    ),
    _rx(
        r"\b(?:(?:деньги|перевод|оплата|платеж)\s+)?"
        r"(?:(?:еще|пока|до\s+сих\s+пор|так\s+и)\s+)?не\s+"
        r"(?:пришл[аио]|пришел|дошл[аио]|дошел|поступил[аио]?|"
        r"прошел|прошла|прошло|зачислен[аыо]?|получен[аоы]?|"
        r"выполнен[ао]?|исполнен[ао]?)\b"
    ),
    _rx(
        r"\b(?:перевод|оплата|платеж|операция|транзакция)\s+"
        r"(?:отменен[ао]?|отклонен[ао]?|неуспешен|неуспешна)\b"
    ),
    _rx(r"\bнет\s+(?:оплаты|перевода|платежа|поступления)\b"),
    _rx(r"\bбез\s+(?:оплаты|перевода|платежа)\b"),
    _rx(r"\b(?:ошибка|отказ)\s+(?:при\s+)?(?:оплате|переводе|платеже)\b"),
    _rx(r"\bнедостаточно\s+средств\b"),
)

_REVERSAL_PATTERNS = (
    _rx(r"\b(?:вернул|вернула|вернули)\s+(?:деньги|оплату|перевод|платеж)\b"),
    _rx(r"\bвозврат\s+(?:денег|оплаты|перевода|платежа)\b"),
    _rx(
        r"\b(?:возвратил|возвратила|отменил|отменила)\s+"
        r"(?:деньги|оплату|перевод|платеж)\b"
    ),
    _rx(
        r"\b(?:деньги|перевод|оплата|оплату|платеж)\s+"
        r"(?:вернул(?:и|ся|ась|ось|ись)?|возвратил(?:и|ся|ась|ось|ись)?|"
        r"отменил(?:а|и)?|отменен[аоы]?)\b"
    ),
    _rx(
        r"\b(?:скинул(?:а|и)?|кинул(?:а|и)?|отправил(?:а|и)?|"
        r"закинул(?:а|и)?|перевел(?:а|и)?)\s+"
        r"(?:деньги\s+)?(?:назад|обратно)\b"
    ),
    _rx(r"\b(?:сделал(?:а|и)?|оформил(?:а|и)?)\s+возврат\b"),
    _rx(r"\bвозврат\s+(?:на\s+)?\d"),
    _rx(r"\bвернул(?:а|и)?\s+\d"),
)

_AMOUNT_RE = _rx(
    r"(?<![\w])"
    r"(?P<prefix>[$€₽])?\s*"
    r"(?P<number>\d{1,3}(?:[ .\u00a0\u202f]\d{3})+(?:[.,]\d{1,2})?|\d{1,7}(?:[.,]\d{1,2})?)"
    r"\s*(?P<scale>к|тыс(?:яч[аиу]?)?\.?)?\s*"
    r"(?P<currency>₽|руб(?:л(?:ь|я|ей))?\.?|р\.|usd|usdt|доллар(?:а|ов)?|\$|eur|евро|€)?"
    r"(?![\w])"
)

_STRUCTURED_NUMBER_RE = _rx(
    r"(?<!\w)(?:\+?\d[\d\s()\-./•·∙‧]{5,}\d)(?!\w)"
)

_IDENTIFIER_PREFIX_RE = _rx(
    r"(?:"
    r"(?:номер\s+)?(?:заказа|операции|транзакции|платежа|перевода|"
    r"счета|карты|телефона)|"
    r"заказ|order(?:\s+id)?|id|операци[яи]|транзакци[яи]|"
    r"карт(?:а|ы|е|у)|телефон(?:а|у)?|счет(?:а|у)?|аккаунт(?:а|у)?|"
    r"чек(?:а|у)?|код(?:а)?|артикул"
    r")\s*(?:№|#|:|id)?\s*(?:[xх*•]+\s*)?$"
)

_BARE_ID_MARKER_RE = _rx(r"(?:№|#|\bid\s*[:=]?)\s*$")

_LAST_DIGITS_PREFIX_RE = _rx(
    r"(?:карт(?:а|ы|е|у)|телефон(?:а|у)?|счет(?:а|у)?)\s*:?\s+"
    r"(?:заканчивается\s+на|последни[ея]\s+(?:четыре|4)\s+цифр[ыи]?)\s*$"
)

_NON_AMOUNT_UNIT_RE = _rx(
    r"^\s*(?:"
    r"шт\.?|штук[аи]?|фото(?:к|чк[аи]?|графи[йяюи])?|картин(?:ок|ки|ка)|"
    r"файл(?:ов|а|ы)?|документ(?:ов|а|ы)?|сообщени(?:й|я|е)|"
    r"видео|ссыл(?:ок|ки|ка)|контакт(?:ов|а|ы)?|чат(?:ов|а|ы)?|"
    r"пост(?:ов|а|ы)?|скрин(?:ов|а|ы|шотов)?|"
    r"билет(?:ов|а|ы)?|товар(?:ов|а|ы)?|мест(?:о|а)?|"
    r"изменени(?:й|я|е)|страниц(?:а|ы)?|строк(?:а|и)?|слов(?:о|а)?|"
    r"предложени(?:й|я|е)|задач(?:а|и)?|заказ(?:ов|а|ы)?|цифр(?:а|ы)?|"
    r"просмотр(?:ов|а|ы)?|подписчик(?:ов|а|и)?|балл(?:ов|а|ы)?|"
    r"заяв(?:ок|ки|ка)|лид(?:ов|а|ы)?|лайк(?:ов|а|и)?|"
    r"минут(?:ы|у)?|час(?:ов|а)?|дн(?:ей|я)|лет|год(?:а|ов)?"
    r")\b|^\s*%"
)

_NON_PAYMENT_NUMERIC_ACTION_RE = _rx(
    r"\b(?:скинь|скиньте|отправь|отправьте|закинь|закиньте)\s+"
    r"(?:мне\s+)?\d[\d\s.,]*\s+"
    r"(?:фото(?:к|чк[аи]?|графи[йяюи])?|картин(?:ок|ки|ка)|файл(?:ов|а|ы)?|"
    r"документ(?:ов|а|ы)?|сообщени(?:й|я|е)|видео|ссыл(?:ок|ки|ка)|"
    r"просмотр(?:ов|а|ы)?|подписчик(?:ов|а|и)?|балл(?:ов|а|ы)?|"
    r"заяв(?:ок|ки|ка)|лид(?:ов|а|ы)?|лайк(?:ов|а|и)?)\b"
)

_NON_PAYMENT_QUANTITY_RE = _rx(
    r"(?<!\w)\d[\d\s.,]*(?:к|тыс(?:яч[аиу]?)?\.?)?\s+"
    r"(?:фото(?:к|чк[аи]?|графи[йяюи])?|просмотр(?:ов|а|ы)?|"
    r"подписчик(?:ов|а|и)?|балл(?:ов|а|ы)?|заяв(?:ок|ки|ка)|"
    r"лид(?:ов|а|ы)?|лайк(?:ов|а|и)?)\b"
)

_NON_PAYMENT_OBJECT_RE = _rx(
    r"\b(?:текст[а-я]*|перевод\s+текста|фото(?:к|чк[а-я]*|графи[а-я]*)?|"
    r"картин[а-я]*|файл[а-я]*|документ[а-я]*|сообщени[а-я]*|"
    r"видео|ссылк[а-я]*|контакт[а-я]*|субтитр[а-я]*|слова?|предложени[а-я]*|"
    r"просмотр[а-я]*|подписчик[а-я]*|балл[а-я]*|заяв[а-я]*|"
    r"лид[а-я]*|лайк[а-я]*)\b"
)


def _normalise(value: str | None) -> str:
    if not value:
        return ""
    return _SPACE_RE.sub(" ", str(value).replace("ё", "е").replace("Ё", "Е")).strip().lower()


def _metadata_value(metadata: Mapping[str, Any] | None, *keys: str) -> Any:
    if not metadata:
        return None
    for key in keys:
        if key in metadata:
            return metadata[key]
    return None


def _normalise_direction(direction: str | None) -> str:
    value = _normalise(direction)
    if value in {"incoming", "in", "inbound", "входящее", "входящий"}:
        return "incoming"
    if value in {"outgoing", "out", "outbound", "исходящее", "исходящий"}:
        return "outgoing"
    return "unknown"


def _normalise_media_type(media_type: str | None) -> str | None:
    value = _normalise(media_type)
    if not value:
        return None
    if value.startswith("image/") or value in {"photo", "image", "screenshot", "фото"}:
        return "image"
    if value in {"application/pdf", "pdf"}:
        return "pdf"
    if value.startswith("video/") or value == "video":
        return "video"
    if value.startswith("audio/") or value in {"audio", "voice"}:
        return "audio"
    return "document"


def _matches(patterns: tuple[re.Pattern[str], ...], text: str) -> list[re.Match[str]]:
    found: list[re.Match[str]] = []
    for pattern in patterns:
        found.extend(pattern.finditer(text))
    return sorted(found, key=lambda match: (match.start(), match.end()))


def _evidence(category: str, matches: list[re.Match[str]]) -> list[dict[str, str]]:
    # Deduplication keeps the response compact when two regexes cover one phrase.
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for match in matches:
        value = _SPACE_RE.sub(" ", match.group(0)).strip()
        if value and value not in seen:
            rows.append({"category": category, "match": value})
            seen.add(value)
    return rows


def _currency_code(raw: str | None) -> str:
    value = _normalise(raw).rstrip(".")
    if value in {"$", "usd"} or value.startswith("доллар"):
        return "USD"
    if value in {"€", "eur", "евро"}:
        return "EUR"
    if value == "usdt":
        return "USDT"
    return "RUB"


def _parse_number(raw: str, scale: str | None) -> int | float:
    compact = raw.replace(" ", "").replace("\u00a0", "").replace("\u202f", "")
    if "," in compact and "." in compact:
        decimal_mark = "," if compact.rfind(",") > compact.rfind(".") else "."
        grouping_mark = "." if decimal_mark == "," else ","
        compact = compact.replace(grouping_mark, "").replace(decimal_mark, ".")
    elif "," in compact or "." in compact:
        mark = "," if "," in compact else "."
        tail = compact.rsplit(mark, 1)[1]
        if len(tail) == 3:
            compact = compact.replace(mark, "")
        else:
            compact = compact.replace(mark, ".")
    value = float(compact)
    if scale:
        value *= 1000
    return int(value) if value.is_integer() else value


def _looks_like_date_or_time(text: str, start: int, end: int) -> bool:
    around = text[max(0, start - 2) : min(len(text), end + 2)]
    return bool(
        re.search(r"\d[:.]\d", around)
        or re.search(r"\d{1,2}[./-]\d{1,2}", around)
        or re.search(r"\d{4}-\d", around)
    )


def _overlaps(left: re.Match[str], right: re.Match[str]) -> bool:
    return left.start() < right.end() and right.start() < left.end()


def _without_overlaps(
    matches: list[re.Match[str]],
    blockers: list[re.Match[str]],
) -> list[re.Match[str]]:
    if not blockers:
        return matches
    return [match for match in matches if not any(_overlaps(match, blocker) for blocker in blockers)]


def _question_marks_for_claims(
    text: str,
    claims: list[re.Match[str]],
) -> list[re.Match[str]]:
    """Return question marks that belong to a nearby payment-success claim."""

    questions: list[re.Match[str]] = []
    for question in _QUESTION_MARK_RE.finditer(text):
        for claim in claims:
            if claim.end() > question.start() or question.start() - claim.end() > 80:
                continue
            between = text[claim.end() : question.start()]
            if not re.search(r"[.!?]", between):
                questions.append(question)
                break
    return questions


def _looks_like_structured_identifier(text: str, start: int, end: int) -> bool:
    """Recognise a phone/card/account sequence containing this number span."""

    for candidate in _STRUCTURED_NUMBER_RE.finditer(text):
        if candidate.start() >= end or candidate.end() <= start:
            continue
        raw = candidate.group(0)
        digits = re.sub(r"\D", "", raw)
        # A grouped amount such as «100 000» must remain an amount.  Phones,
        # cards and bank accounts normally contain at least eight digits; a
        # leading plus, brackets or hyphens make seven digits sufficient.
        formatted_as_contact = any(char in raw for char in "+()-")
        if len(digits) >= 8 or (formatted_as_contact and len(digits) >= 7):
            return True
    return False


def _looks_like_labelled_identifier(text: str, start: int) -> bool:
    prefix = text[max(0, start - 64) : start]
    if _BARE_ID_MARKER_RE.search(prefix) or _LAST_DIGITS_PREFIX_RE.search(prefix):
        return True
    label = _IDENTIFIER_PREFIX_RE.search(prefix)
    if not label:
        return False

    # «перевёл на карту 5000» and «на счёт 5000» commonly put an unmarked
    # amount after the destination.  Explicit identifier wording still wins.
    if (
        re.search(r"\bна\s+(?:карту|счет)\s*$", prefix)
        and not re.search(r"(?:номер|№|#|\bid\b|[xх*•]{2,})\s*$", prefix)
    ):
        return False
    return True


def _looks_like_non_amount_unit(text: str, end: int) -> bool:
    return bool(_NON_AMOUNT_UNIT_RE.search(text[end : min(len(text), end + 40)]))


def _extract_amounts(text: str, *, allow_bare: bool) -> list[dict[str, Any]]:
    amounts: list[dict[str, Any]] = []
    seen: set[tuple[int | float, str]] = set()
    for match in _AMOUNT_RE.finditer(text):
        explicit = match.group("prefix") or match.group("currency") or match.group("scale")
        if not explicit and not allow_bare:
            continue
        number_start = match.start("number")
        number_end = match.end("number")
        if (
            _looks_like_structured_identifier(text, number_start, number_end)
            or _looks_like_non_amount_unit(text, match.end())
        ):
            continue
        if not explicit:
            if (
                _looks_like_date_or_time(text, number_start, number_end)
                or _looks_like_labelled_identifier(text, number_start)
            ):
                continue

        digits = re.sub(r"\D", "", match.group("number"))
        if not explicit and (len(digits) > 7 or (len(digits) == 4 and digits.startswith(("19", "20")))):
            continue

        currency_raw = match.group("prefix") or match.group("currency")
        value = _parse_number(match.group("number"), match.group("scale"))
        currency = _currency_code(currency_raw)
        key = (value, currency)
        if key in seen:
            continue
        seen.add(key)
        amounts.append(
            {
                "value": value,
                "currency": currency,
                "raw": _SPACE_RE.sub(" ", match.group(0)).strip(),
                "currency_explicit": bool(currency_raw or match.group("scale")),
                # Internal-only span used to tell «отправил 5000 за фото» from
                # «отправил 30 фото за 5000».  It is removed from public output.
                "_start": match.start("number"),
            }
        )
    return amounts


def _action_leads_to_amount(
    text: str,
    actions: list[re.Match[str]],
    amounts: list[dict[str, Any]],
) -> bool:
    for action in actions:
        for amount in amounts:
            if not (amount["currency_explicit"] or abs(float(amount["value"])) >= 100):
                continue
            amount_start = int(amount["_start"])
            if amount_start < action.end():
                continue
            between = text[action.end() : amount_start]
            if len(between) <= 40 and not _NON_PAYMENT_OBJECT_RE.search(between):
                return True
    return False


def analyze_payment_signal(
    text: str | None = None,
    *,
    caption: str | None = None,
    direction: str | None = "unknown",
    media_type: str | None = None,
    is_forwarded: bool = False,
    is_quote: bool = False,
    media_metadata: Mapping[str, Any] | None = None,
    allow_bare_amounts: bool | None = None,
) -> dict[str, Any]:
    """Return a conservative review signal for a Russian payment message.

    ``is_forwarded`` and ``is_quote`` mean that the text cannot be directly
    attributed to the current sender.  They therefore reduce confidence and
    make ``success_claim`` false even if the quoted words describe a transfer.
    ``media_metadata`` is optional and may contain ``type``/``mime_type`` and
    the two attribution flags; explicit keyword arguments take precedence.
    ``allow_bare_amounts``: when False, ignore numbers without ₽/руб/тыс —
    important for noisy OCR that invents digit junk like ``30108``.
    """

    metadata_media = _metadata_value(media_metadata, "type", "kind", "mime_type")
    if media_type is None and metadata_media:
        media_type = str(metadata_media)
    if not is_forwarded:
        is_forwarded = bool(_metadata_value(media_metadata, "is_forwarded", "forwarded"))
    if not is_quote:
        is_quote = bool(_metadata_value(media_metadata, "is_quote", "quoted"))

    normalised_direction = _normalise_direction(direction)
    normalised_media = _normalise_media_type(media_type)
    parts = [_normalise(text), _normalise(caption)]
    body = " ".join(part for index, part in enumerate(parts) if part and part not in parts[:index])

    negation_matches = _matches(_NEGATION_PATTERNS, body)
    reversal_matches = _matches(_REVERSAL_PATTERNS, body)
    negative_matches = negation_matches + reversal_matches
    non_payment_numeric_matches = list(_NON_PAYMENT_NUMERIC_ACTION_RE.finditer(body))
    non_payment_numeric_matches.extend(_NON_PAYMENT_QUANTITY_RE.finditer(body))

    # A positive regex is allowed to match inside an explicitly negative
    # phrase only for discovery; it must not survive as a positive category.
    completed_matches = _without_overlaps(
        list(_COMPLETED_RE.finditer(body)), negative_matches
    )
    intent_matches = _without_overlaps(
        list(_INTENT_RE.finditer(body)), negative_matches
    )
    purchase_matches = _without_overlaps(
        list(_PURCHASE_RE.finditer(body)), negative_matches
    )
    request_matches = _without_overlaps(
        _matches(_REQUEST_PATTERNS, body), negative_matches + non_payment_numeric_matches
    )
    method_matches = _matches(_METHOD_PATTERNS, body)
    receipt_matches = _matches(_RECEIPT_PATTERNS, body)
    confirmation_matches = _without_overlaps(
        _matches(_CONFIRMATION_PATTERNS, body), negative_matches + non_payment_numeric_matches
    )
    lexical_uncertainty_matches = _matches(_UNCERTAINTY_PATTERNS, body)
    question_uncertainty_matches = _question_marks_for_claims(
        body, completed_matches + confirmation_matches
    )
    context_matches = list(_PAYMENT_CONTEXT_RE.finditer(body))
    money_context_matches = list(_MONEY_CONTEXT_RE.finditer(body))
    transfer_destination_matches = list(_TRANSFER_DESTINATION_RE.finditer(body))
    non_payment_object_matches = list(_NON_PAYMENT_OBJECT_RE.finditer(body))
    work_object_matches = list(_WORK_OBJECT_RE.finditer(body))

    generic_completed_matches = [
        match for match in completed_matches if _GENERIC_COMPLETED_RE.fullmatch(match.group(0))
    ]
    inherent_completed_matches = [
        match
        for match in completed_matches
        if _INHERENT_PAYMENT_COMPLETED_RE.fullmatch(match.group(0))
    ]
    other_completed_matches = [
        match
        for match in completed_matches
        if match not in generic_completed_matches and match not in inherent_completed_matches
    ]
    generic_intent_matches = [
        match for match in intent_matches if _GENERIC_INTENT_RE.fullmatch(match.group(0))
    ]
    inherent_intent_matches = [
        match
        for match in intent_matches
        if _INHERENT_PAYMENT_INTENT_RE.fullmatch(match.group(0))
    ]
    other_intent_matches = [
        match
        for match in intent_matches
        if match not in generic_intent_matches and match not in inherent_intent_matches
    ]

    # A lone «чек» accompanying an image/PDF is a weak review clue.  Without a
    # document it remains ignored, because receipts for ordinary purchases are
    # far too common to count as transfer evidence.
    weak_receipt_matches = list(_RECEIPT_WORD_RE.finditer(body))
    receipt_with_media = bool(weak_receipt_matches and normalised_media in {"image", "pdf"})
    if receipt_with_media and not receipt_matches:
        receipt_matches = weak_receipt_matches

    verify_matches = _matches(_VERIFY_PATTERNS, body)
    money_talk_matches = _matches(_MONEY_TALK_PATTERNS, body)
    has_transaction_language = bool(
        completed_matches
        or intent_matches
        or purchase_matches
        or request_matches
        or method_matches
        or receipt_matches
        or confirmation_matches
        or negation_matches
        or reversal_matches
    )
    if allow_bare_amounts is None:
        allow_bare = has_transaction_language
    else:
        allow_bare = bool(allow_bare_amounts)
    amounts = _extract_amounts(body, allow_bare=allow_bare)
    strong_bare_amount = any(
        item["currency_explicit"] or abs(float(item["value"])) >= 100
        for item in amounts
    )
    explicit_currency_amount = any(item["currency_explicit"] for item in amounts)
    uncertain = bool(
        question_uncertainty_matches
        or (
            lexical_uncertainty_matches
            and (
                completed_matches
                or confirmation_matches
                or intent_matches
                or purchase_matches
                or request_matches
                or (method_matches and amounts)
            )
        )
    )
    uncertainty_matches = lexical_uncertainty_matches + question_uncertainty_matches
    generic_leading_amount = _action_leads_to_amount(body, generic_completed_matches, amounts)
    other_completed_leading_amount = _action_leads_to_amount(body, other_completed_matches, amounts)
    generic_intent_leading_amount = _action_leads_to_amount(body, generic_intent_matches, amounts)
    other_intent_leading_amount = _action_leads_to_amount(body, other_intent_matches, amounts)
    confirmation_contextual = bool(
        confirmation_matches
        and (
            not non_payment_object_matches
            or amounts
            or money_context_matches
            or method_matches
        )
    )

    categories: list[str] = []
    evidence: list[dict[str, str]] = []

    def add(category: str, matches: list[re.Match[str]]) -> None:
        if matches:
            categories.append(category)
            evidence.extend(_evidence(category, matches))

    add("transfer_completed", completed_matches)
    add("payment_confirmation", confirmation_matches)
    add("payment_intent", intent_matches)
    add("purchase_intent", purchase_matches)
    add("payment_request", request_matches)
    add("payment_method", method_matches)
    add("receipt", receipt_matches)
    add("payment_negation", negation_matches)
    add("refund_or_reversal", reversal_matches)
    if uncertain:
        add("payment_uncertain", uncertainty_matches)
    if amounts:
        categories.append("amount")
    # «проверяй» засчитываем только рядом с деньгами — иначе это «проверь почту».
    verify_contextual = bool(
        verify_matches
        and (
            amounts
            or money_context_matches
            or method_matches
            or receipt_matches
            or completed_matches
            or confirmation_matches
        )
    )
    if verify_contextual:
        add("payment_verify_request", verify_matches)

    token_count = len(_TOKEN_RE.findall(body))
    category_count = len({
        category
        for category in categories
        if category not in {"amount", "payment_negation", "refund_or_reversal"}
    })
    request_contextual = bool(
        request_matches
        and (
            any(not re.search(r"\d", match.group(0)) for match in request_matches)
            or strong_bare_amount
            or method_matches
            or money_context_matches
        )
    )
    completed_contextual = bool(
        inherent_completed_matches
        or (
            other_completed_matches
            and (
                method_matches
                or receipt_matches
                or other_completed_leading_amount
                or (strong_bare_amount and not non_payment_object_matches)
                or (
                    (money_context_matches or context_matches)
                    and not non_payment_object_matches
                )
            )
        )
        or (
            generic_completed_matches
            and (
                generic_leading_amount
                or (strong_bare_amount and not non_payment_object_matches)
                or receipt_matches
                or transfer_destination_matches
                or (money_context_matches and not non_payment_object_matches)
            )
        )
    )
    intent_contextual = bool(
        inherent_intent_matches
        or (
            other_intent_matches
            and (
                method_matches
                or other_intent_leading_amount
                or (strong_bare_amount and not non_payment_object_matches)
                or (
                    (money_context_matches or context_matches)
                    and not non_payment_object_matches
                )
            )
        )
        or (
            generic_intent_matches
            and (
                generic_intent_leading_amount
                or (strong_bare_amount and not non_payment_object_matches)
                or receipt_matches
                or transfer_destination_matches
                or (money_context_matches and not non_payment_object_matches)
            )
        )
    )
    purchase_contextual = bool(
        purchase_matches
        and (
            explicit_currency_amount
            or (strong_bare_amount and not non_payment_object_matches)
            or method_matches
            or money_context_matches
            or work_object_matches
        )
    )
    contextual = bool(
        body
        and (
            receipt_with_media
            or (
                token_count >= 2
                and (
                    request_contextual
                    or confirmation_contextual
                    or (negation_matches and (context_matches or amounts))
                    or reversal_matches
                    or completed_contextual
                    or intent_contextual
                    or purchase_contextual
                    or (method_matches and amounts)
                    or (receipt_matches and amounts)
                )
            )
        )
    )

    score = 0.0
    if completed_matches:
        score += 0.34
    if confirmation_matches:
        score += 0.44
    if intent_matches:
        score += 0.25
    if purchase_matches:
        score += 0.12
    if request_matches:
        score += 0.30
    if method_matches:
        score += 0.15
    if receipt_matches:
        score += 0.27
    if amounts:
        score += 0.20
    if negation_matches:
        score += 0.18
    if reversal_matches:
        score += 0.28

    if completed_matches and amounts:
        score += 0.16
    if completed_matches and (method_matches or receipt_matches):
        score += 0.12
    if confirmation_matches and amounts:
        score += 0.10
    if request_matches and method_matches:
        score += 0.10
    if intent_matches and amounts:
        score += 0.10
    elif intent_matches and context_matches:
        score += 0.06
    if purchase_matches and (amounts or method_matches):
        score += 0.12
    elif purchase_matches and work_object_matches:
        score += 0.18
    if inherent_intent_matches and not amounts and not method_matches:
        score += 0.08
    if receipt_matches and normalised_media in {"image", "pdf"}:
        score += 0.10
    if category_count >= 3:
        score += 0.06

    if (
        generic_completed_matches
        and not inherent_completed_matches
        and not other_completed_matches
        and not confirmation_matches
        and not method_matches
        and not receipt_matches
    ):
        # A bare colloquial assertion such as «скинул 5000» is useful for
        # review, but without bank/method/receipt context it is not strong
        # enough to be a high-confidence success signal.
        score = min(score, 0.61)

    negated = bool(negation_matches or reversal_matches)
    if negated:
        # A failed/reversed payment remains audit-relevant but is never proof
        # that money was received.
        score = min(score * 0.72 + 0.12, 0.69)
    elif uncertain:
        score = min(score, 0.58)

    attributable = not is_forwarded and not is_quote
    if is_forwarded:
        score *= 0.55
    if is_quote:
        score *= 0.70
    if not contextual:
        score = min(score, 0.24)

    score = round(min(max(score, 0.0), 1.0), 2)
    if score >= 0.75:
        level = "high"
    elif score >= 0.48:
        level = "medium"
    elif score >= 0.30:
        level = "low"
    else:
        level = "none"

    detected = bool(contextual and level != "none")
    if negated:
        event_status = "failed_or_reversed"
    elif uncertain:
        event_status = "uncertain"
    elif completed_matches or confirmation_matches:
        event_status = "completed"
    elif receipt_matches:
        event_status = "receipt"
    elif request_matches:
        event_status = "requested"
    elif intent_matches or purchase_matches:
        event_status = "intent"
    else:
        event_status = "possible"

    if is_forwarded and is_quote:
        attribution = "forwarded_quote"
    elif is_forwarded:
        attribution = "forwarded"
    elif is_quote:
        attribution = "quote"
    else:
        attribution = "direct"

    success_claim = bool(
        detected
        and attributable
        and not negated
        and not uncertain
        and (completed_matches or confirmation_matches)
    )

    # Страховочная сеть. Рабочие чаты часто удаляют сразу после заказа, поэтому
    # лучше сохранить слабый денежный след, чем не сохранить ничего: сам разговор
    # о деньгах уже был, даже если он не тянет на полноценный сигнал.
    money_mentioned = bool(
        inherent_completed_matches
        or inherent_intent_matches
        or method_matches
        or receipt_matches
        or confirmation_matches
        or negation_matches
        or reversal_matches
        or request_matches
        or money_context_matches
        or verify_contextual
        or (amounts and not non_payment_object_matches)
        or (money_talk_matches and not non_payment_object_matches)
    )

    return {
        "detected": detected,
        "money_mentioned": money_mentioned,
        # Улики и суммы для слабого следа: заполнены даже тогда, когда сигнал не
        # набрал на полноценный, — иначе в карточке было бы пусто.
        "money_evidence": evidence + _evidence("money_talk", money_talk_matches),
        "money_amounts": [
            {key: value for key, value in item.items() if not key.startswith("_")}
            for item in amounts
        ],
        "categories": categories if contextual else [],
        "amounts": [
            {key: value for key, value in item.items() if not key.startswith("_")}
            for item in amounts
        ] if contextual else [],
        "confidence": score,
        "level": level,
        "event_status": event_status if contextual else "none",
        "success_claim": success_claim,
        "negated": negated,
        "negation_reasons": [row["match"] for row in _evidence("negation", negation_matches + reversal_matches)],
        "uncertain": bool(uncertain and contextual),
        "uncertainty_reasons": [
            row["match"] for row in _evidence("uncertainty", uncertainty_matches)
        ] if contextual else [],
        "attribution": attribution,
        "attributable": attributable,
        "direction": normalised_direction,
        "media_type": normalised_media,
        "evidence": evidence if contextual else [],
        "requires_review": detected,
    }


# Short alias for call sites that naturally deal in messages rather than audit
# records.  Keeping one implementation also keeps scoring deterministic.
analyze_message = analyze_payment_signal
