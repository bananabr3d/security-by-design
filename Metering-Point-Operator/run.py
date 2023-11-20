from app import app
# === Import routes ===
from app.routes import routes

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)