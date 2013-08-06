# -*- coding: utf-8 -*-
"""
    flask.ext.informal
    ~~~~~~~~~~~~~~~~~~

    Adds form abstraction and helpers to your Flask application.

    :copyright: (c) 2011 by Philip Nelson.
    :license: BSD, see LICENSE for more details.
"""
import copy
import os
import re

from collections import OrderedDict
from datetime import datetime
from urlparse import urljoin, urlparse

from flask import current_app, redirect, request, session, url_for
from werkzeug import cached_property
from werkzeug.exceptions import BadRequest

class ValidationError(Exception):
    """The exception representing an error during validation."""
    pass

class FieldBase(type):

    def __new__(cls, name, bases, attrs):
        messages = {}

        # messages from higher bases override lower
        for base in reversed(bases):
            if hasattr(base, 'messages'):
                messages.update(base.messages)

        # finally add messages from current field
        if 'messages' in attrs:
            messages.update(attrs['messages'])

        attrs['messages'] = messages

        return type.__new__(cls, name, bases, attrs)

class Field(object):
    """The base class for all form field types.

    :param name: The name used for the field in the template.
    :param default: The default value for :attr:`data` in place of null data.
    :param required: The boolean value indicating if the field is required to
                     be in the incoming form data.
    :param validators: A list of additional validators to run on validation.
    """

    __metaclass__ = FieldBase

    messages = dict(required="Required.")

    # TODO: validators overwrite the validators applied in FormBase
    def __init__(self, name=None, default=None, required=True, validators=None):
        self.name = name
        self.default = default
        self.required = required
        self.validators = validators or []

        #: The key the field is known as internally.
        self.key = None
        #: A list of errors applied during validation.
        self.errors = []
        #: The actual data associated with the field.
        self.data = None

    def convert(self, values):
        """Takes the list of values and returns the converted value for this
        field type. When called by the :class:`Form`, :attr:`data` will be
        populated with the result.
        """
        return values

    def validate(self):
        """Run through the list of validators associated with the field. This
        includes specified :attr:`validators` as well as validators inferred
        by convention. Validators may raise a :class:`ValidationError`
        exception to add error messages to the field.
        """
        for validator in self.validators:
            try:
                # TODO: self.form first param
                validator(self, self.data)
            except ValidationError as error:
                self.errors.append(error.message)
        return not self.errors

    def __str__(self):
        """Return a string representation of the data to properly render
        pre-populated edit forms.
        """
        return str(self.data) if self.data is not None else ""

    def __repr__(self):
        return "<%s(%r)>" % (self.__class__.__name__, self.data)

class String(Field):
    """A string field.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param min: The minimum length of the string.
    :param max: The maximum length of the string.
    """

    messages = dict(
        min="Must be at least %d characters.",
        max="Must be at most %d characters."
    )

    def __init__(self, name=None, default=None, required=True, validators=None,
                 min=None, max=None):
        Field.__init__(self, name, default, required, validators)
        self.min = min
        self.max = max

    def convert(self, values):
        """Accepts incoming form data and returns a single string. Use the
        :attr:`min` attribute to validate that the string is not empty.
        """
        rv = values and values[0] or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return None

        return rv

    def validate(self):
        """Validates the string length by comparing to both :attr:`min` and
        :attr:`max` before standard validation.
        """
        if self.min is not None and len(self.data) < self.min:
            self.errors.append(self.messages['min'] % self.min)

        if self.max is not None and len(self.data) > self.max:
            self.errors.append(self.messages['max'] % self.max)

        return Field.validate(self)

class ByteString(String):
    """A UTF-8 encoded string field.

    Takes the same parameters as a standard :class:`String`.
    """

    def convert(self, values):
        """Accepts incoming form data and returns a single UTF-8 encoded
        string. Use the :attr:`min` attribute to validate that the string is
        not empty.
        """
        rv = String.convert(self, values)
        if rv is not None:
            rv = rv.encode("utf-8")
        return rv

# TODO: can't deepcopy / pickle so kind of useless at the moment
class RegEx(String):
    """A string field matched against a regular expression.

    Takes the following parameters in addition to a standard :class:`String`::

    :param pattern: A string or compiled :class:`~re.RegexObject`.
    """

    messages = dict(invalid="Invalid.")

    def __init__(self, name=None, default=None, required=True, validators=None,
                 min=None, max=None, pattern=None, flags=0):
        String.__init__(self, name, default, required, validators, min, max)
        self.regex = re.compile(pattern, flags)

    def validate(self):
        """Validates the regular expression by matching it to the field data
        before standard validation.
        """
        if not self.regex.match(self.data):
            self.errors.append(self.messages['invalid'])
        return String.validate(self)

class Email(RegEx):
    """A string field matched against a preconfigured regular expression.

    Takes the same parameters as a standard :class:`String`.
    """

    def __init__(self, name=None, default=None, required=True, validators=None,
                 min=None, max=None):
        RegEx.__init__(self, name, default, required, validators, min, max,
            "^[\w+\-.]+@[a-z\d\-.]+\.[a-z]+$", re.IGNORECASE)

class Integer(Field):
    """An integer field.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param min: The minimum value of the integer.
    :param max: The maximum value of the integer.
    """

    messages = dict(
        invalid="Invalid.",
        min="Must be at least %d.",
        max="Must be at most %d."
    )

    def __init__(self, name=None, default=None, required=True, validators=None,
                 min=None, max=None):
        Field.__init__(self, name, default, required, validators)
        self.min = min
        self.max = max

    def convert(self, values):
        """Accepts incoming form data and returns an integer. An empty string
        will be validated against during the invalid integer check.
        """
        rv = values and values[0] or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return None

        try:
            rv = int(rv)
        except ValueError:
            self.errors.append(self.messages['invalid'])
            return None

        return rv

    def validate(self):
        """Validates the integer value by comparing to both :attr:`min` and
        :attr:`max` before standard validation.
        """
        if self.min is not None and self.data < self.min:
            self.errors.append(self.messages['min'] % self.min)

        if self.max is not None and self.data > self.max:
            self.errors.append(self.messages['max'] % self.max)

        return Field.validate(self)

class Float(Field):
    """A float field.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param min: The minimum value of the float.
    :param max: The maximum value of the float.
    """

    messages = dict(
        invalid="Invalid.",
        min="Must be at least %d.",
        max="Must be at most %d."
    )

    def __init__(self, name=None, default=None, required=True, validators=None,
                 min=None, max=None):
        Field.__init__(self, name, default, required, validators)
        self.min = min
        self.max = max

    def convert(self, values):
        """Accepts incoming form data and returns a float. An empty string
        will be validated against during the invalid float check. Special
        case-insensitive edge cases 'inf' and '-inf' are still valid floats.
        """
        rv = values and values[0] or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return None

        try:
            rv = float(rv)
        except ValueError:
            self.errors.append(self.messages['invalid'])
            return None

        return rv

    def validate(self):
        """Validates the float value by comparing to both :attr:`min` and
        :attr:`max` before standard validation.
        """
        if self.min is not None and self.data < self.min:
            self.errors.append(self.messages['min'] % self.min)

        if self.max is not None and self.data > self.max:
            self.errors.append(self.messages['max'] % self.max)

        return Field.validate(self)

class Boolean(Field):
    """A boolean field.

    Takes the same parameters as a standard :class:`Field`.
    """

    def convert(self, values):
        """Accepts incoming form data and returns a boolean. An empty string
        is considered **False** as the field name will not be found in the
        incoming form data. Any non-empty string will be considered **True**.
        """
        rv = values and values[0] or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return False

        return bool(rv)

    def __str__(self):
        return "1" if self.data else ""

class Date(Field):
    """A date field.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param format: The format string for conversion.
    """

    def __init__(self, name=None, default=None, required=True, validators=None,
                 format=None):
        Field.__init__(self, name, default, required, validators)
        self.format = format or "%Y-%m-%d"

    def convert(self, values):
        """Accepts incoming form data and returns a date. An empty string
        will be validated against during the invalid integer check.
        """
        rv = values and values[0] or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return None

        try:
            rv = datetime.strptime(rv, self.format).date()
        except ValueError:
            self.errors.append(self.messages['invalid'])
            return None

        return rv

class Time(Field):
    """A time field.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param format: The format string for conversion.
    """

    def __init__(self, name=None, default=None, required=True, validators=None,
                 format=None):
        Field.__init__(self, name, default, required, validators)
        self.format = format or "%H:%M:%S"
    
    def convert(self, values):
        """Accepts incoming form data and returns a time. An empty string
        will be validated against during the invalid time check. The return
        value is not timezone aware but in most use cases the user will have
        provided a time in their timezone. It is recommended to override this
        method and convert the result to UTC for internal use, but remain
        timezone unaware. When later interfacing with the user, convert the
        time back to the user's timezone. This all assumes you have a means
        of retrieving the user's timezone from something like a profile option
        or client-side detection.

        See `http://lucumr.pocoo.org/2011/7/15/eppur-si-muove/`_ for more
        information on best practice.
        """
        rv = values and values[0] or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return None

        try:
            rv = datetime.strptime(rv, self.format).time()
        except ValueError:
            self.errors.append(self.messages['invalid'])
            return None

        return rv

class DateTime(Field):
    """A datetime field.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param format: The format string for conversion.
    """

    def __init__(self, name=None, default=None, required=True, validators=None,
                 format=None):
        Field.__init__(self, name, default, required, validators)
        self.format = format or "%Y-%m-%d %H:%M:%S"

    def convert(self, values):
        """Accepts incoming form data and returns a datetime. An empty string
        will be validated against during the invalid datetime check. The return
        value is not timezone aware but in most use cases the user will have
        provided a time in their timezone. It is recommended to override this
        method and convert the result to UTC for internal use, but remain
        timezone unaware. When later interfacing with the user, convert the
        time back to the user's timezone. This all assumes you have a means
        of retrieving the user's timezone from something like a profile option
        or client-side detection.

        See `http://lucumr.pocoo.org/2011/7/15/eppur-si-muove/`_ for more
        information on best practice.
        """
        rv = values and values[0] or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return None

        try:
            rv = datetime.strptime(rv, self.format)
        except ValueError:
            self.errors.append(self.messages['invalid'])
            return None

        return rv

class Tags(Field):
    """A series of tag fields.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param min: The minimum number of tags.
    :param max: The maximum number of tags.
    :param min_length: The minimum length of an individual tag.
    :param max_length: The maximum length of an individual tag.
    """

    messages = dict(
        min="Must have at least %d tags.",
        max="Must have at most %d tags.",
        min_length="Tag %s must be at least %d characters.",
        max_length="Each %s must be at most %d characters."
    )

    def __init__(self, name=None, default=None, required=True, validators=None,
                 min=None, max=None, min_length=None, max_length=None):
        Field.__init__(self, name, default, required, validators)
        self.min = min
        self.max = max
        self.min_length = min_length
        self.max_length = max_length

    def convert(self, values):
        """TODO"""
        rv = values or self.default

        if rv is None:
            if self.required:
                self.errors.append(self.messages['required'])
            return None

        return rv

    def validate(self):
        """Validates the tag list and each individual tag before standard
        validation. :attr:`min` and :attr:`max` are tests with respect to
        the number of tags. :attr:`min_length` and :attr:`max_length` are
        with respect to the length of each individual tag.
        """
        if self.min is not None and len(self.data) < self.min:
            self.errors.append(self.messages['min'] % self.min)

        if self.max is not None and len(self.data) > self.max:
            self.errors.append(self.messages['max'] % self.max)

        for tag in self.data:
            if self.min_length is not None and len(tag) < self.min_length:
                self.errors.append(self.messages['min_length'] % (
                    tag, self.min_length))

            if self.max_length is not None and len(tag) > self.max_length:
                self.errors.append(self.messages['max_length'] % (
                    tag, self.max_length))

        return Field.validate(self)

class Upload(Field):
    """TODO"""

    def __init__(self, name=None, default=None, required=True, validators=None,
                 whitelist=None):
        Field.__init__(self, name, default, required, validators)
        self.whitelist = frozenset(whitelist or [])

    def convert(self, values):
        """TODO"""
        rv = values or self.default
        return rv

    def validate(self):
        """TODO"""
        if "." in filename and filename.rsplit(".", 1)[1] in self.whitelist:
            self.errors.append(self.messages['filename'] % filename)

class CSRFToken(Field):
    """A field to store the CSRF token.

    Takes the following parameters in addition to a standard :class:`Field`::

    :param size: The number of random bytes used to generate the CSRF token.
    :param callback: A callable executed on detected CSRF attempts.
    """

    #: A whitelist of RFC 2616 section 9.1.1 Safe Methods.
    safe_methods = frozenset(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

    def __init__(self, name=None, default=None, required=True, validators=None,
                 size=16, callback=None):
        Field.__init__(self, name, default, required, validators)
        self.size = size
        self.callback = callback

    def convert(self, values):
        """Converts the list of values to a single field value."""
        return values and values[0] or self.default

    def validate(self):
        """Validates the CSRF token before standard validation. The token is
        compared to what exists in session, generated by simply including
        this field's value in a hidden field. On detected CSRF attempts, a
        predefined callback is executed and then an HTTP 400 Bad Request
        exception is raised.
        """
        if self.required and request.method not in self.safe_methods:
            token = session.pop(self.name, None)
            if token is None or token != self.data:
                if callable(self.callback):
                    self.callback(request.endpoint, request.view_args)
                raise BadRequest

        return Field.validate(self)

    def __str__(self):
        """Generates a 16 character CSRF token to be used in a hidden field."""
        if self.name not in session:
            session[self.name] = os.urandom(self.size).encode("hex")
        return session[self.name]

# TODO: what about `required`?
# TODO: maybe add a callback for unsafe url?
class NextURL(Field):
    """A field to store the next URL. This is often used for the common
    pattern of redirecting after form.

    Takes the same parameters as a standard :class:`Field`.
    """

    def convert(self, values):
        """Returns the redirection URL from either this hidden field or the
        associated GET parameter, but only if they share the same network
        location.
        """
        rv = values and values[0] or \
             request.args.get(self.name) or \
             self.default

        if rv is None or not self.is_safe_url(rv):
            return None

        return rv

    def is_safe_url(self, url):
        """Determines if `url` is considered safe by ensuring the scheme
        belongs to HTTP and that it shares the same network location as the
        request URL.
        """
        this = urlparse(urljoin(request.url_root, url))
        host = urlparse(request.host_url)
        return this.scheme in ('http', 'https') and this.netloc == host.netloc

class FieldDescriptor(object):

    def __init__(self, key):
        self.key = key

    def __get__(self, obj, cls):
        try:
            if obj is None:
                return cls.base_fields[self.key]
            return obj.fields[self.key]
        except KeyError:
            raise AttributeError(self.key)

    def __set__(self, obj, value):
        obj.fields[self.key] = value

    def __delete__(self, obj):
        if self.key not in obj.fields:
            raise AttributeError("%r object has no attribute %r" % (
                type(obj).__name__, self.key))
        del obj.fields[self.key]

class FormBase(type):

    def __new__(cls, name, bases, attrs):
        fields = OrderedDict()
        validators = {}
        parents = [base for base in bases if isinstance(base, FormBase)]

        # add fields from parents
        for parent in parents:
            if hasattr(parent, 'base_fields'):
                fields.update(parent.base_fields)

        # add fields from the current form, modifying attributes
        for key, value in attrs.iteritems():
            if key.startswith("validate_") and callable(value):
                validators[key[9:]] = value
            elif isinstance(value, Field):
                value.key = key
                if value.name is None:
                    value.name = key
                fields[key] = value
                attrs[key] = FieldDescriptor(key)

        # apply the field-specific validators
        for key, value in validators.iteritems():
            if key in fields:
                fields[key].validators.append(value)

        attrs['base_fields'] = fields
        attrs['base_validators'] = validators

        return type.__new__(cls, name, bases, attrs)

class Form(object):
    """The base class for a form.

    :param csrf_protect: Can be set to manually override the CSRF protection
                         setting from the configuration file.
    :param **kwargs: Initial data to add to the form. This data is overwritten
                     by incoming form data immediately, if keys match.
    """

    __metaclass__ = FormBase

    csrf_token = CSRFToken()
    next_url = NextURL()

    def __init__(self, csrf_protect=None, **kwargs):
        #: The dictionary of fields.
        self.fields = copy.deepcopy(self.base_fields)

        #: The dictionary of errors. This is only non-empty when errors are
        #: present after validation. Keys are a fields :attr:`key` attribute.
        #: A special ``__form__`` key will exist for :exc:`ValidationError`s
        #: raised in :meth:`validate`. Values are always lists of errors.
        self.errors = {}

        #: The raw, unvalidated, incoming form data.
        self.raw_data = dict(kwargs)
        self.raw_data.update(request.form.to_dict(flat=False))
        self.raw_data.update(request.files.to_dict(flat=False))

        if current_app.config.get('TESTING', False):
            csrf_protect = False

        if csrf_protect is None:
            csrf_protect = current_app.config.get('INFORMAL_CSRF_PROTECT', True)

        if not csrf_protect:
            self.csrf_token.required = False

    def initialize(self, obj):
        """TODO"""
        for key, field in self.fields.iteritems():
            field.data = getattr(obj, key, None)

    @property
    def submitted(self):
        """Verifies that the form was submitted via POST or PUT."""
        return request.method in ('POST', 'PUT')

    @property
    def valid(self):
        """Abstracts the form validation to allow :meth:`validate` to be
        overridden and raise :exc:`ValidationError`s itself. These errors
        are placed in :attr:`errors` under key ``__form__``.
        """
        try:
            self.validate()
        except ValidationError as error:
            self.errors.setdefault('__form__', []).append(error.message)
        return not self.errors

    def validate(self):
        """Validates the entire form by individually validating each field if
        and only if the field didn't raise errors during :meth:`Field.convert`.
        """
        for field in self.fields.itervalues():
            field.data = field.convert(self.raw_data.get(field.name))
            if not field.errors:
                field.validate()
        self.errors = dict((key, field.errors)
            for key, field in self.fields.iteritems() if field.errors)
        return not self.errors

    def redirect(self, endpoint, next=False, **kwargs):
        """If `next` is **False** this is just a shortcut for redirecting to a
        known `endpoint`. If `next` is **True** this will first attempt to
        redirect to :attr:`next_url` or `endpoint` as a fallback.
        """
        if next:
            return redirect(self.next_url.data or url_for(endpoint, **kwargs))
        return redirect(url_for(endpoint, **kwargs))

    def __getitem__(self, key):
        try:
            field = self.fields[key]
        except KeyError:
            raise KeyError("%r object has no field %r" % (
                self.__class__.__name__, key))
        return field.data

    def __repr__(self):
        return "<%r(%s)>" % (self.__class__.__name__, self.fields.items())
