# Package for environment variables
import os
from dotenv import load_dotenv
load_dotenv()

def verify_all(expected_environment_variables) -> bool:
    '''
    This function verifies if all expected environment variables are available.
    '''
    # Check if all keys available
    if (not set(expected_environment_variables).issubset(dict(os.environ.items()).keys())):
        return False
    return True