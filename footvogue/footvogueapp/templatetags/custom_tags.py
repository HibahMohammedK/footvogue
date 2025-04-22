from django import template

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
