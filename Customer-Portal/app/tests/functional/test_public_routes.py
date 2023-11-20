from pytest import fixture
from app import app

class TestPublicRoutes:
    @fixture(autouse=True)
    def setup(self):
        self.client = app.test_client()

    # GET Requests
    def test_get_home_route(self):
        response = self.client.get('/')
        assert response.status_code == 200

    # def test_get_about_route(self): #TODO
    #     response = self.client.get('/about')
    #     assert response.status_code == 200

    # def test_get_impressum_route(self): #TODO
    #     response = self.client.get('/impressum')
    #     assert response.status_code == 200