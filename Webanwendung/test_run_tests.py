from app import app

from app.tests.unit import verify_env


def test_env():
    expected_environment_variables = ["SECRET_KEY", "MONGODB_USER", "MONGODB_PW", "MONGODB_CLUSTER"]

    # Verify environment variables
    assert verify_env.verify_all(expected_environment_variables=expected_environment_variables) == True


# https://testdriven.io/blog/flask-pytest/