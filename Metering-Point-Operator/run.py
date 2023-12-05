from app import app
# === Import routes ===
from app.routes import routes
from app.API import api_customer, api_electricity_meter

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)