# Posit Connect Cloud static + API proof of concept

This small app tests the deployment shape for the DECISIVE frontend: a public static page and a
same-origin API in one server-side application. The FastAPI app serves `public/index.html` and
implements public reads, an editor login, an editor-only API action, and a ten-minute idle session.

The protected API uses `DEMO_HMAC_SECRET` on the server to sign a message; it returns the signature,
never the secret. This demonstrates an application using a Connect Cloud secret variable without
shipping the variable to browser JavaScript. It does **not** connect to Neo4j or validate any
production security/deployment policy.

## Deploy on Connect Cloud

1. Put this proof of concept in its own **public, non-sensitive GitHub repository**. The Free plan
   supports publishing from public repositories; the repository and its source will be public.
2. In Connect Cloud, choose **Publish**, select the **FastAPI** framework if offered, then select
   the repository, branch, and `app.py` as the primary file.
3. Set these secret variables in the deployment settings:
   - `EDITOR_USERNAME`: a demo-only editor name.
   - `EDITOR_PASSWORD_HASH`: generated using the steps below.
   - `DEMO_HMAC_SECRET`: a fresh random demo value; do not use any real Neo4j secret.
   - `COOKIE_SECURE`: `true` for the HTTPS deployment.
4. Deploy. Open the published URL. The public API status should load without signing in. Use the
   configured editor credentials to call the protected signing endpoint.
5. Inspect the browser Network panel: API calls should be under the app's Connect Cloud URL, for
   example `<published-app-url>/api/public`, `<published-app-url>/api/session`,
   `<published-app-url>/api/login`, and `<published-app-url>/api/sign`. The secret value must never
   appear in page source or response.

Connect Cloud's current GitHub publishing guide says Python projects require `requirements.txt`,
and that encrypted secret variables can be consumed by application code. The exact framework
choices and settings may change; if FastAPI is not offered, this deployment test has not yet
confirmed FastAPI support on the account.

## Generate an editor password hash

Use a local Python installation. The password is prompted without echo:

```sh
python3 make_password_hash.py
```

Copy its output into the Connect Cloud `EDITOR_PASSWORD_HASH` secret variable. Do not commit that
hash or the plain-text password. The hash uses PBKDF2-HMAC-SHA256 with a random salt.

## Run and test locally

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
export EDITOR_USERNAME=poc-editor
export EDITOR_PASSWORD_HASH="$(python3 -c 'from password_hash import encode_password_hash; print(encode_password_hash("local-only-password"))')"
export DEMO_HMAC_SECRET=local-only-demo-secret
export COOKIE_SECURE=false
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. In another terminal, run:

```sh
python -m unittest -v
```

## Security and scope

- The page is public on the Connect Cloud Free plan. The demo login only gates the protected API
  action; it does not make the site private or restrict access by IP.
- Secrets must be configured as Connect Cloud secret variables and read only by the Python app.
  Never put them in `public/index.html`, JavaScript, or a client-side config file.
- Sessions are in-memory for this small deployment test. They are not suitable for a multi-worker,
  replicated, or production deployment without a shared session store and operational review.
- A real application must also account for Connect Cloud plan access controls, database network
  reachability, Neo4j least-privilege roles, secret handling, TLS, logging, and organizational
  approval before using sensitive data.
