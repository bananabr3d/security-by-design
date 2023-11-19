from app import app
# === Import routes ===
from app.routes import routes, contract_routes, auth_routes, error_routes, auth_routes_2fa

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)