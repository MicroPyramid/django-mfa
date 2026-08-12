try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
from django import template
from django.template.defaultfilters import stringfilter
from django.utils.html import conditional_escape, format_html

register = template.Library()


@register.filter
@stringfilter
def qrcode(value, alt=None):
    url = conditional_escape("https://qrcode.tec-it.com/API/QRCode?data=" + value)
    alt = conditional_escape(alt or value)

    return format_html(u"""<img class="qrcode" src="%s" width="150" height="150" alt="%s" />""" % (url, alt))
