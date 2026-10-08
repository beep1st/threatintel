from django import template

register = template.Library()

@register.simple_tag
def query_transform(request_get, **kwargs):
    updated = request_get.copy()
    for k, v in kwargs.items():
        updated[k] = v
    return updated.urlencode()
