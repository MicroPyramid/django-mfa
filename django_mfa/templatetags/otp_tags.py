try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
from django import template
from django.template.defaultfilters import stringfilter
from django.utils.html import conditional_escape
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter
@stringfilter
def qrcode(value, alt=None):
    url = conditional_escape("http://chart.apis.google.com/chart?%s" %
                             urlencode({'chs': '150x150', 'cht': 'qr', 'chl': value, 'choe': 'UTF-8'}))
    alt = conditional_escape(alt or value)

    return mark_safe(u"""<img class="qrcode" src="%s" width="150" height="150" alt="%s" />""" % (url, alt))
