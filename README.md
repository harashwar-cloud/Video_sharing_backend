# SyncStream Backend — FastAPI API Server

This is the server-side application for SyncStream built with FastAPI, SQLite/PostgreSQL, and Uvicorn. It coordinates real-time watch-party synchronization, chat message persistence, and local/cloud video libraries.

---

## 1. Development Setup

### Prerequisite
Ensure you have Python 3.10+ installed.

### Environment Configuration
Verify your `.env` file settings (a default `.env` is configured for SQLite):
```env
PORT=8080
DATABASE_URL=sqlite:///./syncstream.db
FRONTEND_URL=http://localhost:5173
JWT_SECRET=your_jwt_secret_key_here
```

### Installation & Run
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the FastAPI server using Uvicorn:
   ```bash
   uvicorn app.main:app --reload --port 8080
   ```
The server will start locally at [http://localhost:8080](http://localhost:8080).

---

## 2. Deployment on Render

Render can host the backend as a **Web Service** using the provided `Dockerfile`.

### Configuration Steps
1. Create a new **Web Service** on Render and connect your backend repository.
2. Select **Docker** as the Runtime environment.
3. In **Advanced Settings**, add the following environment variables:
   - `PORT`: Set to `8080` (or leave empty; Render passes its own port dynamically, and uvicorn binds to it).
   - `FRONTEND_URL`: Comma-separated list of your deployment frontend URLs (e.g. `https://your-frontend.vercel.app`).
   - `JWT_SECRET`: A secure, random string used to sign JWTs.
   - `DATABASE_URL`: Connection string for your Render PostgreSQL database (e.g., `postgresql://user:pass@host/db`).
   - `GOOGLE_DRIVE_API_KEY`: (Optional) Your Google API key.
4. Deploy the service.

---

## 3. Database Migrations & Schemas
The backend automatically creates and synchronizes all database tables on startup via `Base.metadata.create_all(engine)`. No manual migrations are required for the initial setup.

---

## 4. Docker Run (Local Production Test)
Build and run the container locally:
```bash
docker build -t syncstream-backend .
docker run -p 8080:8080 -e FRONTEND_URL=http://localhost:5173 syncstream-backend
```
