# Web2 security lab

A deliberately vulnerable web application for the second Web2 lab: stored XSS and
sensitive data exposure, each with a switch that turns the vulnerability on and off.

## Run locally

```sh
npm install
cp .env.example .env   # then set POSTGRES_URL
npm run dev
```

The app listens on <http://localhost:3000>. Tables are created on first start.
