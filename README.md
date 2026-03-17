<<<<<<< HEAD
=======
<<<<<<< HEAD
# HYSTERESIS
=======
>>>>>>> 5a16324 (Updated files)
# Hysteresis Clone + MongoDB Login

## Run

```powershell
npm install
npm start
```

Server runs at: `http://localhost:4173`

## Test Login UI

Open: `http://localhost:4173/login.html`

## API

- `POST /api/auth/register`  
  Body: `{ "name": "User", "email": "user@mail.com", "password": "secret123" }`
- `POST /api/auth/login`  
  Body: `{ "email": "user@mail.com", "password": "secret123" }`
- `GET /api/auth/me`  
  Header: `Authorization: Bearer <token>`

## Env

Configured from `.env`:

- `MONGODB_URI`
- `MONGODB_DB`
- `JWT_SECRET`
<<<<<<< HEAD
=======
>>>>>>> 83545fe (Initial commit)
>>>>>>> 5a16324 (Updated files)
