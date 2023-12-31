from app.tests.verify_env import verify_all

def test_environmentvariables():
    expected_environment_variables = ["SECRET_KEY", "JWT_SECRET_KEY", "MONGODB_USER", "MONGODB_PW", "MONGODB_CLUSTER", "MONGODB_SUBDOMAIN", "JWT_ACCESS_TOKEN_EXPIRATION_MINUTES", "2FA_EXPIRATION_MINUTES"]

    assert verify_all(expected_environment_variables=expected_environment_variables) == True


# https://testdriven.io/blog/flask-pytest/