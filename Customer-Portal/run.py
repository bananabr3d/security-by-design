from app import app
# === Import individual routes ===
from app.routes import routes, contract_routes

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)