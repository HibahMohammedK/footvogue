from django import template
from django.templatetags.static import static

register = template.Library()

@register.filter
def times(value):
    """
    Returns a range object to be used in templates for iteration.
    Handles both positive and negative values.
    """
    value = int(value)  # Ensure the input is an integer
    return range(max(0, value))  # Return a range object

@register.filter
def subtract(value, arg):
    """
    Subtracts 'arg' from 'value' and ensures the result is non-negative.
    """
    value = int(value)  # Ensure the inputs are integers
    arg = int(arg)
    return max(0, value - arg)


@register.filter
def image_or_placeholder(variant):
    try:
        return variant.productimage_set.first().image_url.url
    except:
        return static('images/no-image-available.png')

@register.filter(name='add_class')
def add_class(field, css_class):
    return field.as_widget(attrs={'class': css_class})

@register.filter
def in_list(value, arg):
    return value in arg.split(',')

@register.filter
def count_status(items, status):
    return items.filter(status=status).count()