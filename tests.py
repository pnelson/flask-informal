import unittest

from flask import Flask, current_app
from flask.ext.informal import Form, Field, String, Integer, Float, Boolean, \
    Date, Time, DateTime, ValidationError
from werkzeug.exceptions import BadRequest

def create_empty_form():

    class EntityForm(Form):
        tester = Boolean(required=False)

    return EntityForm

def create_basic_form():

    def special_validator(form, value):
        if "special" not in value:
            raise ValidationError("not special")

    class EntityForm(Form):

        a = String(min=3, max=16)
        b = String(required=False, default="test",
                   validators=[special_validator])

        def validate_b(self, value):
            if "test" not in value:
                raise ValidationError("not a test")

    return EntityForm

def create_nested_form():

    class EntityForm(Form):

        a = String()
        b = String()

    class NestedForm(EntityForm):

        c = String()

        def validate(self):
            rv = Form.validate(self)
            if not rv:
                return False
            if "test" not in self.b.data:
                raise ValidationError("invalid")
            return True

    return NestedForm

def test_generic_field():
    def has_2(form, values):
        if 2 not in values:
            raise ValidationError("missing 2")
    def has_4(form, values):
        if 4 not in values:
            raise ValidationError("missing 4")
    field = Field(validators=[has_2, has_4])
    field.data = field.convert([1, 2, 3])
    assert not field.validate()
    assert field.errors == ["missing 4"]

class BaseTest(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.from_object(self)
        self.context = self.app.test_request_context(method="POST")
        self.context.push()

    def tearDown(self):
        self.context.pop()

class TestBasicForm(BaseTest):

    TESTING = True

    def setUp(self):
        BaseTest.setUp(self)
        self.BasicForm = create_basic_form()

    def test_empty(self):
        form = self.BasicForm()
        assert form.submitted
        assert not form.valid
        assert 'a' in form.errors
        assert 'b' in form.errors
        assert form['a'] is None
        assert form['b'] == "test"

    def test_valid(self):
        form = self.BasicForm(a=["basic"], b=["special test"])
        assert form.valid
        assert form['a'] == "basic"
        assert form['b'] == "special test"

    def test_validate(self):
        form = self.BasicForm(a=["basic"], b=["testing"])
        assert not form.valid
        assert 'b' in form.errors
        assert form.errors['b'] == ["not special"]
        assert form['a'] == "basic"
        assert form['b'] == "testing"

class TestNestedForm(BaseTest):

    TESTING = True

    def setUp(self):
        BaseTest.setUp(self)
        self.NestedForm = create_nested_form()

    def test_empty(self):
        form = self.NestedForm()
        assert form.submitted
        assert not form.valid
        assert 'a' in form.errors
        assert 'b' in form.errors
        assert 'c' in form.errors
        assert form['a'] is None
        assert form['b'] is None
        assert form['c'] is None

    def test_valid(self):
        form = self.NestedForm(a=["nested"], b=["testing"], c=["form"])
        assert form.valid
        assert form['a'] == "nested"
        assert form['b'] == "testing"
        assert form['c'] == "form"

    def test_validate(self):
        form = self.NestedForm(a=["nested"], b=["botched"], c=["form"])
        assert not form.valid
        assert '__form__' in form.errors
        assert form.errors['__form__'] == ["invalid"]
        assert form['a'] == "nested"
        assert form['b'] == "botched"
        assert form['c'] == "form"

    def test_delete_field(self):
        form = self.NestedForm(a=["nested"], b=["testing"])
        del form.a
        del form.c
        assert form.valid
        assert form['b'] == "testing"

class TestSecurity(BaseTest):

    TESTING = False
    SECRET_KEY = "testing"

    def setUp(self):
        BaseTest.setUp(self)
        self.Form = create_empty_form()

    def test_csrf_disable_from_config(self):
        self.app.config['INFORMAL_CSRF_PROTECT'] = False
        form = self.Form()
        assert form.valid

    def test_csrf_disable_from_parameter(self):
        form = self.Form(csrf_protect=False)
        assert form.valid

    def test_csrf_enable_from_parameter(self):
        self.app.config['INFORMAL_CSRF_PROTECT'] = False
        form = self.Form(csrf_protect=True)
        self.assertRaises(BadRequest, form.validate)

    def test_csrf_protection_fail(self):
        form = self.Form()
        form.raw_data['csrf_token'] = ["fail"]
        self.assertRaises(BadRequest, form.validate)

    def test_csrf_protection_pass(self):
        form = self.Form()
        form.raw_data['csrf_token'] = [str(form.csrf_token)]
        assert form.valid

class TestString(unittest.TestCase):

    def test_basic(self):
        field = String()
        field.data = field.convert(["test"])
        assert field.data == "test"
        assert field.validate()
        assert field.errors == []

    def test_none(self):
        field = String(required=False)
        field.data = field.convert(None)
        assert field.data is None
        assert field.validate()
        assert field.errors == []

    def test_none_default(self):
        field = String(default="test")
        field.data = field.convert(None)
        assert field.data == "test"
        assert field.validate()
        assert field.errors == []

    def test_none_required(self):
        field = String()
        field.data = field.convert(None)
        assert field.data is None
        assert not field.validate()
        assert field.errors == ["Required."]

    def test_min(self):
        field = String(min=5)
        field.data = field.convert(["test"])
        assert field.data == "test"
        assert not field.validate()
        assert field.errors == ["Must be at least 5 characters."]

    def test_max(self):
        field = String(max=3)
        field.data = field.convert(["test"])
        assert field.data == "test"
        assert not field.validate()
        assert field.errors == ["Must be at most 3 characters."]

class TestInteger(unittest.TestCase):

    def test_basic(self):
        field = Integer()
        field.data = field.convert(["4"])
        assert field.data == 4
        assert field.validate()
        assert field.errors == []

    def test_none(self):
        field = Integer(required=False)
        field.data = field.convert(None)
        assert field.data is None
        assert field.validate()
        assert field.errors == []

    def test_none_default(self):
        field = Integer(default=4)
        field.data = field.convert(None)
        assert field.data == 4
        assert field.validate()
        assert field.errors == []

    def test_none_required(self):
        field = Integer()
        field.data = field.convert(None)
        assert field.data is None
        assert not field.validate()
        assert field.errors == ["Required."]

    def test_min(self):
        field = Integer(min=5)
        field.data = field.convert(["4"])
        assert field.data == 4
        assert not field.validate()
        assert field.errors == ["Must be at least 5."]

    def test_max(self):
        field = Integer(max=3)
        field.data = field.convert(["4"])
        assert field.data == 4
        assert not field.validate()
        assert field.errors == ["Must be at most 3."]

class TestFloat(unittest.TestCase):

    def test_basic(self):
        field = Float()
        field.data = field.convert(["3.14"])
        assert field.data == 3.14
        assert field.validate()
        assert field.errors == []

    def test_none(self):
        field = Float(required=False)
        field.data = field.convert(None)
        assert field.data is None
        assert field.validate()
        assert field.errors == []

    def test_none_default(self):
        field = Float(default=3.14)
        field.data = field.convert(None)
        assert field.data == 3.14
        assert field.validate()
        assert field.errors == []

    def test_none_required(self):
        field = Float()
        field.data = field.convert(None)
        assert field.data is None
        assert not field.validate()
        assert field.errors == ["Required."]

    def test_min(self):
        field = Float(min=5)
        field.data = field.convert(["3.14"])
        assert field.data == 3.14
        assert not field.validate()
        assert field.errors == ["Must be at least 5."]

    def test_max(self):
        field = Float(max=3)
        field.data = field.convert(["3.14"])
        assert field.data == 3.14
        assert not field.validate()
        assert field.errors == ["Must be at most 3."]

class TestBoolean(unittest.TestCase):

    def test_basic(self):
        field = Boolean()
        field.data = field.convert(["1"])
        assert field.data
        assert field.errors == []

    def test_none(self):
        field = Boolean(required=False)
        field.data = field.convert(None)
        assert not field.data
        assert field.validate()
        assert field.errors == []

    def test_none_default(self):
        field = Boolean(default=False)
        field.data = field.convert(None)
        assert not field.data
        assert field.validate()
        assert field.errors == []

    def test_none_required(self):
        field = Boolean()
        field.data = field.convert(None)
        assert not field.data
        assert not field.validate()
        assert field.errors == ["Required."]

class TestDate(unittest.TestCase):

    def test_basic(self):
        field = Date()
        assert False

class TestTime(unittest.TestCase):

    def test_basic(self):
        field = Time()
        assert False

class TestDateTime(unittest.TestCase):

    def test_basic(self):
        field = DateTime()
        assert False

def suite():
    return unittest.TestSuite(tests=[
        unittest.FunctionTestCase(test_generic_field),
        unittest.makeSuite(TestString),
        unittest.makeSuite(TestInteger),
        unittest.makeSuite(TestFloat),
        unittest.makeSuite(TestBoolean),
        #unittest.makeSuite(TestDate),
        #unittest.makeSuite(TestTime),
        #unittest.makeSuite(TestDateTime),
        unittest.makeSuite(TestBasicForm),
        unittest.makeSuite(TestNestedForm),
        unittest.makeSuite(TestSecurity),
    ])

if __name__ == "__main__":
    unittest.main(defaultTest="suite", verbosity=2)
