from app.tests.unit import verify_env

def test_environmentvariables():
    expected_environment_variables = ["SECRET_KEY", "JWT_SECRET_KEY", "MONGODB_USER", "MONGODB_PW", "MONGODB_CLUSTER", "MONGODB_SUBDOMAIN"]

    assert verify_env.verify_all(expected_environment_variables=expected_environment_variables) == True


# https://testdriven.io/blog/flask-pytest/