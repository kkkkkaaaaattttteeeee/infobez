# -*- coding: utf-8 -*-
"""
Анализатор текста на признаки нарушения конфиденциальности.
Backend на Flask: извлечение сущностей, база правил, логический вывод,
маскирование, логирование и обработка действий оператора.
"""
from flask import Flask, render_template, request, jsonify, send_file
import re
import os
import datetime

app = Flask(__name__)
LOG_FILE = "security_log.txt"


# =====================================================================
# СЛОВАРИ СУЩНОСТЕЙ (основы слов — устойчивость к падежам и формам)
# =====================================================================

SUBJECT_KEYWORDS = {
    "сотрудник":   ["сотрудник", "работник", "инженер", "санитар"],
    "клиент":      ["клиент", "пациент", "налогоплательщик"],
    "налоговая":   ["фнс", "налогов", "инспекц"],
    "банк":        ["банк", "кредитн"],
    "врач":        ["врач", "медик", "медучрежден", "больниц"],
    "конкурент":   ["конкурент", "конкурирующ"],
    "третье лицо": ["третье лицо", "адвокат", "нотариус", "полици",
                    "иностранн", "партнёр", "партнер"],
}

OBJECT_KEYWORDS = {
    "ПДн":                ["пдн", "персональн", "база клиент"],
    "коммерческая тайна": ["коммерческ", "секрет производств", "ноу-хау",
                           "исходный код", "алгоритм", "формул", "инновационн"],
    "налоговая тайна":    ["налогов платеж", "налогов тайн", "схем оптимизац",
                           "налогов обязательств", "сведени о налог"],
    "банковская тайна":   ["банковск", "счет", "вклад", "выписк",
                           "операци по счёт"],
    "врачебная тайна":    ["врачебн", "диагноз", "вич", "ветрянк",
                           "медицинск", "снимки мрт"],
}

ACTION_KEYWORDS = {
    "передал":     ["переда", "сообщ", "скид", "скину", "направл",
                    "предостав", "подтверд", "разглас"],
    "запросил":    ["запрос", "запраш", "требу", "потребовал"],
    "опубликовал": ["опубликова", "выложил", "разместил", "пост"],
    "раскрыл":     ["раскры", "разглас", "рассказа", "по секрету", "скажу"],
    "отказал":     ["отказа", "не предоставил"],
}

CONTEXT_KEYWORDS = {
    "согласие":           ["согласи", "согласен", "разрешени"],
    "законное основание": ["законн", "по закону", "в рамках", "115-фз"],
    "проверка":           ["проверк", "аудит", "due diligence", "мониторинг"],
    "суд":                ["суд", "судебн"],
    "конкурент":          ["конкурент"],
    "по секрету":         ["по секрету", "тайно", "неофициально"],
    "документ":           ["письменн", "постановлени", "запрос нотариус", "ордер"],
}


# =====================================================================
# ИЗВЛЕЧЕНИЕ СУЩНОСТЕЙ
# =====================================================================

def extract_entities(text: str) -> dict:
    low = text.lower()
    result = {"subjects": [], "objects": [], "actions": [], "context": []}
    for cat, mapping in [("subjects", SUBJECT_KEYWORDS),
                         ("objects",  OBJECT_KEYWORDS),
                         ("actions",  ACTION_KEYWORDS),
                         ("context",  CONTEXT_KEYWORDS)]:
        for name, keys in mapping.items():
            if any(k in low for k in keys):
                result[cat].append(name)
    return result


# =====================================================================
# МАСКИРОВАНИЕ
# =====================================================================

def mask_text(text: str) -> str:
    """Частично скрывает чувствительные данные."""
    text = re.sub(r'\b[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+\b', '[ФИО]', text)
    text = re.sub(r'\b\d{4,}\b', '[НОМЕР]', text)
    text = re.sub(r'\b\d+[\d\s]*руб\b', '[СУММА]', text, flags=re.IGNORECASE)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                  '[EMAIL]', text)
    text = re.sub(r'\+?\d[\d\s\-()]{9,}\d', '[ТЕЛЕФОН]', text)
    return text


# =====================================================================
# ЛОГИРОВАНИЕ
# =====================================================================

def log_incident(result: dict, original_text: str):
    masked = mask_text(original_text)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"{result['type']} | риск={result['risk_score']} | {masked}\n"
        )


def log_operator_action(action: str, text: str, vtype: str):
    masked = mask_text(text) if text else "[текст удалён оператором]"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"OPERATOR_ACTION={action} | type={vtype} | {masked}\n"
        )


def read_log() -> str:
    if not os.path.exists(LOG_FILE):
        return ""
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return f.read()


# =====================================================================
# ЯДРО: БАЗА ПРАВИЛ И ЛОГИЧЕСКИЙ ВЫВОД
# =====================================================================

def analyze_text(text: str) -> dict:
    """Применяет базу правил и возвращает структурированный вывод."""
    low = text.lower()
    entities = extract_entities(text)
    laws = []          # [{code, article, reason, is_violation}]
    manual = False
    questions = []

    # --- сигналы ---
    has_consent = any(k in low for k in ["согласи", "согласен", "разрешени"])
    has_written_consent = has_consent and "письменн" in low
    has_nda = ("nda" in low or "соглашение о конфиденциальности" in low
               or "соглашение о неразглашении" in low)
    has_written_req = ("письменн" in low and ("запрос" in low or "требован" in low))
    has_audit = ("аудит" in low or "due diligence" in low or "внешн" in low)

    # --- медицина: расширенный контекст ---
    med_ctx = any(w in low for w in [
        "врач", "пациент", "медицинск", "больниц", "санитар", "медик",
        "ветрянк", "вич", "диагноз", "заболева"
    ])

    # --- ПДн: расширенный контекст (включая «данные») ---
    pdn_mentioned = ("пдн" in low or "персональн" in low
                     or ("база" in low and "клиент" in low)
                     or ("данн" in low and ("клиент" in low or "пациент" in low)))
    transfer = any(w in low for w in ["скид", "переда", "направл", "предостав"])

    # --- налоговая тайна ---
    tax_ctx = "фнс" in low or "налогов" in low
    personal_source = any(w in low for w in [
        "сестра", "брат", "друг", "знаком", "родствен",
        "муж", "жена", "сын", "дочь", "отец", "мать", "сват", "кум"
    ])

    # ============ ПРАВИЛО 1. NDA + аудит → законно ============
    if has_nda and has_audit:
        laws.append({
            "code": "98-ФЗ", "article": "ст. 10",
            "reason": "Законно: NDA подписано для внешнего аудита/Due Diligence",
            "is_violation": False,
        })

    # ============ ПРАВИЛО 2. Due Diligence + сделка не состоялась ============
    if "due diligence" in low and ("не состоя" in low or "не заключ" in low) \
            and ("использу" in low or "формул" in low or "алгоритм" in low):
        laws.append({
            "code": "98-ФЗ", "article": "ст. 1465 ГК РФ",
            "reason": "Использование секрета производства после прекращения "
                      "переговоров (преддоговорная ответственность, ст. 434.1 ГК РФ)",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 3. Коммерческая тайна + публикация ============
    if "коммерческ" in low and ("опубликова" in low or "выложил" in low
                                 or "пост" in low) and not has_consent:
        laws.append({
            "code": "98-ФЗ", "article": "ст. 10, ст. 183 УК РФ",
            "reason": "Разглашение коммерческой тайны путём публикации без согласия",
            "is_violation": True,
        })

    # ============ ПРАВИЛА 4+5. Персональные данные (152-ФЗ) ============
    # Объединённое правило: ПДн + передача
    #   - с письменным согласием → законно
    #   - без согласия → нарушение
    if pdn_mentioned and transfer:
        if has_written_consent:
            laws.append({
                "code": "152-ФЗ", "article": "ст. 9",
                "reason": "Законно: письменное согласие субъекта на передачу данных",
                "is_violation": False,
            })
        elif not has_consent:
            laws.append({
                "code": "152-ФЗ", "article": "ст. 6, 9",
                "reason": "Передача персональных данных без согласия субъекта",
                "is_violation": True,
            })
        else:
            # согласие есть, но не письменное — на ручную проверку
            manual = True
            questions.append(
                "Есть ли письменное согласие субъекта на передачу его данных? "
                "Устное согласие не является надлежащим основанием по 152-ФЗ."
            )

    # ============ ПРАВИЛО 6. Врачебная тайна + полиция + устный ============
    if med_ctx and "полици" in low and not has_written_req:
        laws.append({
            "code": "323-ФЗ", "article": "ст. 13",
            "reason": "Нарушение: устный запрос полиции недопустим, "
                      "требуется письменный запрос",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 7. Врачебная тайна + полиция + письменный ============
    if med_ctx and "полици" in low and has_written_req:
        laws.append({
            "code": "323-ФЗ", "article": "ст. 13",
            "reason": "Законно: письменный запрос правоохранительных органов",
            "is_violation": False,
        })

    # ============ ПРАВИЛО 8. Врачебная тайна + «по секрету» / разглашение ============
    if med_ctx and not ("полици" in low) \
            and any(w in low for w in ["по секрету", "разглас", "скажу",
                                       "сообщ", "рассказа", "раскры"]) \
            and not has_consent:
        laws.append({
            "code": "323-ФЗ", "article": "ст. 13",
            "reason": "Разглашение врачебной тайны без согласия пациента",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 9. Врачебная тайна + партнёр + риск ============
    if med_ctx and "партнёр" in low and not has_consent:
        if "угроза жизни" in low or "заражение" in low or "вич" in low:
            manual = True
            questions.append(
                "Есть ли непосредственная угроза жизни партнёра? "
                "Раскрытие возможно только с согласия пациента или по решению суда."
            )
        else:
            laws.append({
                "code": "323-ФЗ", "article": "ст. 13",
                "reason": "Разглашение врачебной тайны партнёру без согласия",
                "is_violation": True,
            })

    # ============ ПРАВИЛО 10. Налоговая тайна + конкурент ============
    if tax_ctx and "конкурент" in low \
            and ("переда" in low or "сообщ" in low or "подтверд" in low) \
            and not has_consent:
        laws.append({
            "code": "146-ФЗ", "article": "ст. 102 НК РФ, ст. 183 УК РФ",
            "reason": "Передача налоговой тайны конкуренту без согласия "
                      "налогоплательщика",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 11. Налоговая тайна + налоговый орган + проверка ============
    if tax_ctx and ("налогов орган" in low or "налогов инспекц" in low) \
            and ("проверк" in low or "аудит" in low):
        laws.append({
            "code": "146-ФЗ", "article": "ст. 102 НК РФ",
            "reason": "Законное исключение: запрос в рамках налоговой проверки",
            "is_violation": False,
        })

    # ============ ПРАВИЛО 12. Налоговая тайна + банк + 115-ФЗ ============
    if "банк" in low and tax_ctx and ("115-фз" in low or "проверк" in low) \
            and ("запраш" in low or "запрос" in low):
        laws.append({
            "code": "146-ФЗ", "article": "ст. 102 НК РФ",
            "reason": "Законное исключение: запрос банка в рамках 115-ФЗ "
                      "(ПОД/ФТ)",
            "is_violation": False,
        })

    # ============ ПРАВИЛО 13. Налоговая тайна + журналист ============
    if tax_ctx and "журналист" in low:
        laws.append({
            "code": "146-ФЗ", "article": "ст. 102 НК РФ, ст. 183 УК РФ",
            "reason": "Утечка налоговой тайны журналисту (нарушение режима "
                      "налоговой тайны)",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 14. ФНС + подтвердила + личный источник ============
    if "фнс" in low and "подтверд" in low \
            and "проверк" not in low and "запрос" not in low \
            and personal_source:
        laws.append({
            "code": "146-ФЗ", "article": "ст. 102 НК РФ, ст. 183 УК РФ",
            "reason": "Косвенная утечка налоговой тайны через сотрудника ФНС, "
                      "сообщившего данные личному контакту",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 15. Банковская тайна + нотариус + отказ ============
    if "банк" in low and "нотариус" in low and "отказа" in low:
        laws.append({
            "code": "395-1-ФЗ", "article": "ст. 26, ст. 1171 ГК РФ",
            "reason": "Нарушение: банк отказал нотариусу при законном запросе "
                      "по счетам умершего клиента",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 16. Банковская тайна + нотариус + запрос ============
    if "банк" in low and "нотариус" in low and ("запрос" in low or "запраш" in low) \
            and "отказа" not in low:
        laws.append({
            "code": "395-1-ФЗ", "article": "ст. 26",
            "reason": "Законно: нотариус вправе запрашивать сведения "
                      "о счетах умершего клиента",
            "is_violation": False,
        })

    # ============ ПРАВИЛО 17. Банковская тайна + иностранная компания ============
    if "банк" in low and "иностранн" in low \
            and ("счет" in low or "данн" in low) \
            and "договор" not in low and "международн" not in low:
        laws.append({
            "code": "395-1-ФЗ", "article": "ст. 26, 152-ФЗ, ст. 12",
            "reason": "Передача банковской тайны иностранной компании "
                      "без международного договора и судебного поручения",
            "is_violation": True,
        })

    # ============ ПРАВИЛО 18. Банковская тайна + Росфинмониторинг ============
    if "банк" in low and ("росфинмониторинг" in low or "подозрительн" in low) \
            and ("переда" in low or "сообщ" in low):
        laws.append({
            "code": "115-ФЗ", "article": "ст. 7",
            "reason": "Законно: банк обязан сообщать о подозрительных "
                      "операциях в Росфинмониторинг",
            "is_violation": False,
        })

    # ============ ПРАВИЛО 19. Государственная тайна ============
    if "пусков" in low or "теракт" in low or ("военн" in low and "тайна" in low):
        manual = True
        questions.append(
            "Возможна государственная тайна. Требуется экспертная проверка "
            "и обращение в уполномоченные органы."
        )

    # ============ ПРАВИЛО 20. Недостаточно данных ============
    if not laws and not manual:
        if not entities["objects"] and not entities["actions"]:
            manual = True
            questions.append("Уточните объект (ПДн, коммерческая, "
                             "налоговая, банковская, врачебная тайна).")
            questions.append("Уточните действие (передал, запросил, "
                             "опубликовал, раскрыл, отказал).")
        else:
            manual = True
            questions.append("Недостаточно контекста для однозначного вывода. "
                             "Уточните получателя информации и наличие согласия.")

    # ============ ИТОГ ============
    violations = [l for l in laws if l["is_violation"]]
    legal = [l for l in laws if not l["is_violation"]]

    if violations:
        vtype = "нарушение"
        action = "mask"
        violation = True
    elif legal:
        vtype = "законное действие"
        action = "nothing"
        violation = False
    elif manual:
        vtype = "требуется ручная проверка"
        action = "manual"
        violation = False
    else:
        vtype = "нет нарушения"
        action = "nothing"
        violation = False

    # Риск-скор
    risk = 0
    risk += 60 * len(violations)
    risk += 15 * len(legal)
    if manual:
        risk = max(risk, 50)
    risk = min(risk, 100)

    # Краткое резюме
    if violations:
        codes = ", ".join(sorted({v["code"] for v in violations}))
        summary = f"Обнаружено нарушение: {codes}"
    elif legal:
        summary = "Все действия законны при наличии указанных оснований"
    elif manual:
        summary = "Требуется ручная проверка специалистом"
    else:
        summary = "Признаков нарушения не найдено"

    return {
        "type": vtype,
        "violation": violation,
        "laws": laws,
        "entities": entities,
        "manual": manual,
        "questions": questions,
        "action": action,
        "masked_text": mask_text(text),
        "risk_score": risk,
        "summary": summary,
    }


# =====================================================================
# REST API
# =====================================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Пустой текст"}), 400
    result = analyze_text(text)
    if result["violation"] or result["manual"]:
        log_incident(result, text)
    return jsonify(result)


@app.route("/api/analyze_file", methods=["POST"])
def api_analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "Файл не приложен"}), 400
    f = request.files["file"]
    try:
        text = f.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return jsonify({"error": f"Не удалось прочитать файл: {e}"}), 400
    if not text.strip():
        return jsonify({"error": "Файл пуст"}), 400
    result = analyze_text(text)
    if result["violation"] or result["manual"]:
        log_incident(result, text)
    result["source_text"] = text
    return jsonify(result)


@app.route("/api/action", methods=["POST"])
def api_action():
    data = request.get_json(silent=True) or {}
    action = data.get("action", "unknown")
    text = data.get("text", "")
    vtype = data.get("type", "")
    if action not in ("deleted", "masked", "ignored"):
        return jsonify({"error": "Неизвестное действие"}), 400
    log_operator_action(action, text, vtype)
    return jsonify({"status": "ok", "action": action})


@app.route("/api/log", methods=["GET"])
def api_log():
    return jsonify({"content": read_log()})


@app.route("/api/log/clear", methods=["POST"])
def api_log_clear():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    return jsonify({"status": "ok"})


@app.route("/api/log/download", methods=["GET"])
def api_log_download():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w", encoding="utf-8").close()
    return send_file(LOG_FILE, as_attachment=True,
                     download_name="security_log.txt")


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
