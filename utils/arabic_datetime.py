"""تنسيق التاريخ والوقت حسب المعيار الإلزامي بمشروعنا: YYYY/M/Dم H:MMص أو H:MMم."""

from markupsafe import Markup


def format_arabic_datetime(value):
    if value is None:
        return ""

    month = value.month
    day = value.day
    hour_24 = value.hour
    minute = value.minute

    period = "ص" if hour_24 < 12 else "م"
    hour_12 = hour_24 % 12
    hour_12 = 12 if hour_12 == 0 else hour_12

    date_part = f"{value.year}/{month}/{day}"
    time_part = f"{hour_12}:{minute:02d}"

    return Markup(
        f'<span class="ar-date">{date_part}<span class="ar-cal">م</span></span> '
        f'<span class="ar-time">{time_part}<span class="ar-ampm">{period}</span></span>'
    )
