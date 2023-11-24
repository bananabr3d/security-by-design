FROM python:latest

WORKDIR /app

# Copy Strength-Meter and Password match
COPY ./Customer-Portal/app/static/password-strength-meter.js ./app/static/password-strength-meter.js
COPY ./Customer-Portal/app/static/passwords-match.js ./app/static/passwords-match.js

# Copy routes
COPY ./Customer-Portal/app/routes/error_routes.py ./app/routes/error_routes.py
COPY ./Customer-Portal/app/routes/auth_routes.py ./app/routes/auth_routes.py
COPY ./Customer-Portal/app/routes/auth_routes_2fa.py ./app/routes/auth_routes_2fa.py

# Copy verify_env
COPY ./Customer-Portal/app/tests/verify_env.py ./app/tests/verify_env.py

# Copy __init__.py
COPY ./Customer-Portal/app/__init__.py ./app/__init__.py

# Copy requirements.txt from Customer-Portal
COPY ./Customer-Portal/requirements.txt requirements.txt

RUN pip3 install --upgrade pip

RUN pip3 install -r requirements.txt

# Copy requirements.txt from Metering-Point-Operator
COPY ./Metering-Point-Operator/requirements.txt requirements-MPO.txt

RUN pip3 install -r requirements-MPO.txt

# Copy all from Metering-Point-Operator
COPY ./Metering-Point-Operator/ ./
ENV PYTHONUNBUFFERED=1

CMD [ "python3", "run.py"]