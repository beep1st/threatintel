# App/templatetags/extra_filters.py
from django import template

register = template.Library()

# App/templatetags/mitre_filters.py
from django import template

register = template.Library()

@register.filter
def multiply(value, arg):
    """Multiply the value by the argument."""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0

@register.filter
def percentage(value, total):
    """Calculate percentage."""
    try:
        if total == 0:
            return 0
        return (float(value) / float(total)) * 100
    except (ValueError, TypeError):
        return 0

@register.filter
def get_item(dictionary, key):
    """Get item from dictionary."""
    return dictionary.get(key)

@register.filter
def format_tech_id(tech_id):
    """Format technique ID for display."""
    if tech_id and '.' in tech_id:
        parts = tech_id.split('.')
        return f"{parts[0]}.<small>{parts[1]}</small>"
    return tech_id
@register.filter
def split(value, delimiter):
    """Split string by delimiter"""
    return value.split(delimiter) if value else []

@register.filter
def get_item(value, index):
    """Get list item by index"""
    try:
        return value[int(index)]
    except:
        return ""

@register.filter
def truncatechars_middle(value, length=24):
    """Show first 16 + ... + last 8 chars of hash"""
    try:
        length = int(length)
        if len(value) <= length:
            return value
        return f"{value[:16]}...{value[-8:]}"
    except:
        return value
    
# App/templatetags/extra_filters.py
from django import template

register = template.Library()

@register.filter
def split(value, delimiter):
    """Split string by delimiter"""
    return value.split(delimiter) if value else []

@register.filter
def get_item(value, index):
    """Get list item by index"""
    try:
        return value[int(index)]
    except:
        return ""

@register.filter
def truncatechars_middle(value, length=24):
    """Show first 16 + ... + last 8 chars of hash"""
    try:
        length = int(length)
        if len(value) <= length:
            return value
        return f"{value[:16]}...{value[-8:]}"
    except:
        return value

@register.filter
def trim(value):
    """Remove whitespace from beginning and end"""
    return value.strip() if value else ""

@register.filter
def second(value):
    """
    Returns the second element (index 1) of a list or string iterable.
    Falls back to the full value if list is too short or not a list.
    """
    if isinstance(value, (list, tuple)) and len(value) > 1:
        return value[1]
    return value or 'Unknown'

@register.filter
def lower(value):
    """Convert string to lowercase"""
    return value.lower() if value else ""

@register.filter
def upper(value):
    """Convert string to uppercase"""
    return value.upper() if value else ""