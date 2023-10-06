# Package for environment variables
import os
from dotenv import load_dotenv
load_dotenv()

expected_environment_variables = ["SECRET_KEY", "MONGODB_USER", "MONGODB_PW", "MONGODB_CLUSTER"]

def verify_all() -> bool:
    # Check if all keys available
    if (not set(expected_environment_variables).issubset(dict(os.environ.items()).keys())):
        return False
    #if (os.getenv)
    return True