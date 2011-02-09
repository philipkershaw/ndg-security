from pylonsapp.tests import *

class TestSecuredController(TestController):

    def test_index(self):
        response = self.app.get(url(controller='secured', action='index'))
        # Test response...
