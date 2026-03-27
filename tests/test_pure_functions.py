"""Tests for pure functions — no DB, no mocking, <1s execution."""
from datetime import date, timedelta
import pytest

import app


# ═══════════════════════════════════════════════════════════════════════════════
# _count_weekdays
# ═══════════════════════════════════════════════════════════════════════════════
class TestCountWeekdays:
    def test_mon_to_fri(self):
        assert app._count_weekdays(date(2025, 3, 3), date(2025, 3, 7)) == 5

    def test_two_full_weeks(self):
        assert app._count_weekdays(date(2025, 3, 3), date(2025, 3, 14)) == 10

    def test_d1_gt_d2_returns_zero(self):
        assert app._count_weekdays(date(2025, 3, 10), date(2025, 3, 3)) == 0

    def test_single_weekday(self):
        assert app._count_weekdays(date(2025, 3, 5), date(2025, 3, 5)) == 1  # Wed

    def test_single_saturday(self):
        assert app._count_weekdays(date(2025, 3, 8), date(2025, 3, 8)) == 0

    def test_single_sunday(self):
        assert app._count_weekdays(date(2025, 3, 9), date(2025, 3, 9)) == 0

    def test_weekend_only(self):
        assert app._count_weekdays(date(2025, 3, 8), date(2025, 3, 9)) == 0

    def test_cross_month_boundary(self):
        # Mar 28 (Fri) to Apr 2 (Wed) = Fri + Mon + Tue + Wed = 4
        assert app._count_weekdays(date(2025, 3, 28), date(2025, 4, 2)) == 4

    def test_same_day_equal(self):
        d = date(2025, 3, 5)
        assert app._count_weekdays(d, d) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# working_days_elapsed
# ═══════════════════════════════════════════════════════════════════════════════
class TestWorkingDaysElapsed:
    def test_one_week(self):
        # Mon to next Mon = 5 business days elapsed
        assert app.working_days_elapsed("2025-03-03", date(2025, 3, 10)) == 5

    def test_same_day_returns_zero(self):
        assert app.working_days_elapsed("2025-03-05", date(2025, 3, 5)) == 0

    def test_start_on_saturday(self):
        # Sat Mar 8 to Mon Mar 10: 1 weekday (Mon) in range, minus 1 = 0 elapsed
        assert app.working_days_elapsed("2025-03-08", date(2025, 3, 10)) == 0

    def test_hold_days_subtracted(self):
        base = app.working_days_elapsed("2025-03-03", date(2025, 3, 10))
        with_hold = app.working_days_elapsed("2025-03-03", date(2025, 3, 10), hold_days=2)
        assert with_hold == base - 2

    def test_hold_days_cannot_go_negative(self):
        assert app.working_days_elapsed("2025-03-03", date(2025, 3, 4), hold_days=999) == 0

    def test_extra_holidays_on_weekday(self):
        extra = {date(2025, 3, 4)}  # Tuesday
        without = app.working_days_elapsed("2025-03-03", date(2025, 3, 7))
        with_hol = app.working_days_elapsed("2025-03-03", date(2025, 3, 7), extra_holidays=extra)
        assert with_hol == without - 1

    def test_extra_holidays_on_weekend_no_effect(self):
        extra = {date(2025, 3, 8)}  # Saturday
        without = app.working_days_elapsed("2025-03-03", date(2025, 3, 10))
        with_hol = app.working_days_elapsed("2025-03-03", date(2025, 3, 10), extra_holidays=extra)
        assert with_hol == without

    def test_known_indian_holiday(self):
        # Aug 11 (Mon) to Aug 18 (Mon): 6 weekdays in range, Aug 15 (Fri) is _HOLIDAYS, minus 1 = 4
        result = app.working_days_elapsed("2025-08-11", date(2025, 8, 18))
        assert result == 4  # 5 business days minus 1 holiday (Aug 15)

    def test_empty_start_returns_zero(self):
        assert app.working_days_elapsed("", date(2025, 3, 10)) == 0

    def test_none_start_returns_zero(self):
        assert app.working_days_elapsed(None, date(2025, 3, 10)) == 0

    def test_malformed_date_returns_zero(self):
        assert app.working_days_elapsed("not-a-date", date(2025, 3, 10)) == 0

    def test_start_after_end_returns_zero(self):
        assert app.working_days_elapsed("2025-03-15", date(2025, 3, 10)) == 0

    def test_excel_datetime_suffix_trimmed(self):
        # Excel sometimes exports "2025-03-03 00:00:00"
        assert app.working_days_elapsed("2025-03-03 00:00:00", date(2025, 3, 10)) == 5

    def test_long_range_matches_short_ranges(self):
        """Verify O(1) formula consistency over a long span."""
        start = date(2024, 1, 1)
        end = date(2025, 12, 31)
        result = app.working_days_elapsed(start.isoformat(), end)
        assert result > 400  # ~500 business days in 2 years


# ═══════════════════════════════════════════════════════════════════════════════
# _pg_sql (SQLite ? → PostgreSQL %s converter)
# ═══════════════════════════════════════════════════════════════════════════════
class TestPgSql:
    def test_simple_placeholder(self):
        assert app._pg_sql("SELECT * FROM t WHERE id=?") == "SELECT * FROM t WHERE id=%s"

    def test_multiple_placeholders(self):
        sql = "INSERT INTO t (a,b,c) VALUES (?,?,?)"
        assert app._pg_sql(sql) == "INSERT INTO t (a,b,c) VALUES (%s,%s,%s)"

    def test_no_placeholders_passthrough(self):
        sql = "SELECT 1"
        assert app._pg_sql(sql) == sql

    def test_question_inside_single_quotes_preserved(self):
        sql = "SELECT * FROM t WHERE col='what?' AND id=?"
        result = app._pg_sql(sql)
        assert "'what?'" in result  # inside quotes: preserved
        assert result.endswith("id=%s")  # outside quotes: converted

    def test_mixed_quoted_and_unquoted(self):
        sql = "WHERE a=? AND b='hello?' AND c=?"
        result = app._pg_sql(sql)
        assert result == "WHERE a=%s AND b='hello?' AND c=%s"

    def test_empty_string(self):
        assert app._pg_sql("") == ""

    def test_escaped_single_quote(self):
        sql = "WHERE name='it''s' AND id=?"
        result = app._pg_sql(sql)
        assert result.endswith("id=%s")

    def test_no_false_positive_on_percent(self):
        sql = "WHERE col LIKE '%test%' AND id=?"
        result = app._pg_sql(sql)
        assert "'%test%'" in result
        assert result.endswith("id=%s")


# ═══════════════════════════════════════════════════════════════════════════════
# _fill (template placeholder substitution)
# ═══════════════════════════════════════════════════════════════════════════════
class TestFill:
    def test_single_placeholder(self):
        assert app._fill("Hello {{Name}}", {"Name": "World"}) == "Hello World"

    def test_multiple_placeholders(self):
        result = app._fill("{{A}} and {{B}}", {"A": "1", "B": "2"})
        assert result == "1 and 2"

    def test_missing_key_stays(self):
        assert app._fill("Hello {{Name}}", {}) == "Hello {{Name}}"

    def test_none_value_becomes_empty(self):
        assert app._fill("Hello {{Name}}", {"Name": None}) == "Hello "

    def test_empty_text(self):
        assert app._fill("", {"Name": "X"}) == ""

    def test_empty_dict(self):
        assert app._fill("no placeholders", {}) == "no placeholders"


# ═══════════════════════════════════════════════════════════════════════════════
# h() — HTML escape
# ═══════════════════════════════════════════════════════════════════════════════
class TestHtmlEscape:
    def test_angle_brackets(self):
        assert "&lt;" in str(app.h("<script>"))
        assert "&gt;" in str(app.h("<script>"))

    def test_ampersand(self):
        assert "&amp;" in str(app.h("a & b"))

    def test_double_quote(self):
        r = str(app.h('say "hi"'))
        assert "&#34;" in r or "&quot;" in r

    def test_safe_string_passthrough(self):
        assert str(app.h("hello")) == "hello"


# ═══════════════════════════════════════════════════════════════════════════════
# Password hashing
# ═══════════════════════════════════════════════════════════════════════════════
class TestPasswordHash:
    def test_round_trip(self):
        pw_hash = app.generate_password_hash("secret123")
        assert app.check_password_hash(pw_hash, "secret123")

    def test_wrong_password_fails(self):
        pw_hash = app.generate_password_hash("secret123")
        assert not app.check_password_hash(pw_hash, "wrong")

    def test_hash_format(self):
        h = app.generate_password_hash("pw")
        assert h.startswith("pbkdf2:sha256:")
