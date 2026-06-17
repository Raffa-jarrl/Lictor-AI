# Check — Debug & admin doors left open in production

**What you're looking for:** the developer tools you used while *building* the app — verbose error pages, debug mode, API explorers, dashboards, source maps — that got shipped to the live site by accident. Every one of these is a window into your app that you meant to keep private. When `debug = true` ships to prod, a single error page can spill your environment variables, database queries, and file paths to a stranger. When Swagger or GraphQL introspection ships, an attacker gets a full map of every endpoint you have. These aren't "hacks" — the door is just standing open.

This is one of the most common ways AI-built apps leak. The AI scaffolds the project in *development* mode (debug on, explorers on, stack traces verbose) because that's what helps you build. Nobody flips the switches off before deploy.

## How to scan

You're hunting for six different open doors. Scan for each across every stack — your users build with anything.

### Door 1 — Debug mode left on

```bash
# Django, Flask, Rails, Laravel, generic
grep -rEn --exclude-dir={node_modules,.next,dist,vendor,.git,build} \
  -e 'DEBUG\s*=\s*True' \
  -e 'FLASK_DEBUG\s*=\s*1' \
  -e 'app\.run\([^)]*debug\s*=\s*True' \
  -e 'config\.consider_all_requests_local\s*=\s*true' \
  -e "APP_DEBUG\s*=\s*true" \
  -e 'app\.debug\s*=\s*true' \
  . 2>/dev/null

# Node/Express: detailed errors / stack traces sent to client
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -e 'errorhandler\(\)' \
  -e 'res\.(send|json)\([^)]*err\.stack' \
  -e 'app\.set\(\s*["'"'"']env["'"'"']\s*,\s*["'"'"']development' \
  . 2>/dev/null

# The .env files themselves
grep -rEn --include='.env*' \
  -e 'DEBUG\s*=\s*(true|1|True)' \
  -e 'APP_ENV\s*=\s*(local|development)' \
  -e 'APP_DEBUG\s*=\s*true' \
  -e 'FLASK_ENV\s*=\s*development' \
  -e 'NODE_ENV\s*=\s*development' \
  . 2>/dev/null
```

### Door 2 — Verbose / stack-trace error pages

```bash
# Frameworks that show a debug error page when an exception is thrown
grep -rEn --exclude-dir={node_modules,.next,dist,vendor,.git} \
  -e 'whoops|Whoops' \
  -e 'werkzeug.*debug' \
  -e 'better_errors' \
  -e 'web-console' \
  -e 'DebugExceptionHandler|UseDeveloperExceptionPage' \
  . 2>/dev/null

# Go: returning err.Error() straight to the HTTP response
grep -rEn --include='*.go' \
  -e 'http\.Error\([^,]+,\s*err\.Error\(\)' \
  -e 'fmt\.Fprintf?\(w,\s*"%v",\s*err' \
  . 2>/dev/null
```

### Door 3 — Spring Boot Actuator exposed

```bash
grep -rEn --exclude-dir={node_modules,target,build,.git} \
  -e 'management\.endpoints\.web\.exposure\.include\s*=\s*\*' \
  -e 'management\.endpoint\.(env|heapdump|threaddump|shutdown|beans|mappings)\.enabled\s*=\s*true' \
  -e 'spring-boot-starter-actuator' \
  . 2>/dev/null
```

`include=*` is the smell: it un-gates every actuator endpoint, including `/actuator/env` (dumps your config + secrets) and `/actuator/heapdump` (dumps live memory).

### Door 4 — API explorers / introspection in prod (Swagger, GraphQL)

```bash
# Swagger / OpenAPI UI mounted unconditionally
grep -rEn --include='*.ts' --include='*.js' --include='*.py' --include='*.go' --include='*.rb' --include='*.php' \
  --exclude-dir={node_modules,.next,dist,vendor} \
  -e 'swagger-ui|swaggerUi|SwaggerUIBundle' \
  -e 'FastAPI\([^)]*' \
  -e 'redoc|ReDoc|rapidoc' \
  -e 'app\.UseSwagger' \
  . 2>/dev/null

# GraphQL introspection / playground left enabled
grep -rEn --exclude-dir={node_modules,.next,dist,vendor} \
  -e 'introspection\s*:\s*true' \
  -e 'graphiql\s*:\s*true' \
  -e 'playground\s*:\s*true' \
  -e 'ApolloServerPluginLandingPageLocalDefault' \
  . 2>/dev/null
```

For **FastAPI** specifically: it serves `/docs` (Swagger) and `/redoc` automatically *unless* you pass `docs_url=None, redoc_url=None`. So a bare `FastAPI()` in a production app is a finding — the explorer is on by default.

### Door 5 — Admin dashboards bundled to ship (Grafana, Adminer, pgAdmin, Mongo Express, etc.)

```bash
# docker-compose / k8s manifests that ship an admin tool alongside the app
grep -rEn --include='docker-compose*.y*ml' --include='*.yaml' --include='*.yml' \
  -e 'adminer' \
  -e 'grafana/grafana' \
  -e 'dpage/pgadmin' \
  -e 'mongo-express' \
  -e 'phpmyadmin' \
  -e 'redis-commander' \
  . 2>/dev/null

# ...and whether their ports are published to the host (the dangerous part)
grep -rEn --include='docker-compose*.y*ml' \
  -e '8080:8080|3000:3000|8081:8081|5050:80|8082:8081' \
  . 2>/dev/null

# Default creds that ship with those tools
grep -rEn --exclude-dir={node_modules,.git} \
  -e 'GF_SECURITY_ADMIN_PASSWORD\s*=\s*admin' \
  -e 'PGADMIN_DEFAULT_PASSWORD' \
  -e 'ME_CONFIG_BASICAUTH' \
  . 2>/dev/null
```

### Door 6 — Source maps shipped to prod

```bash
# Built source maps sitting in the deploy/output folder
find . -path ./node_modules -prune -o \
  \( -name '*.js.map' -o -name '*.css.map' \) -print 2>/dev/null \
  | grep -E '(dist|build|out|\.next|public|static)/' | head -20

# Build config that explicitly keeps maps on in production
grep -rEn --include='*.config.*' --include='*.json' --exclude-dir=node_modules \
  -e 'sourcemap\s*:\s*true' \
  -e 'productionBrowserSourceMaps\s*:\s*true' \
  -e 'GENERATE_SOURCEMAP\s*=\s*true' \
  -e 'devtool\s*:\s*["'"'"']source-map' \
  . 2>/dev/null
```

### Mobile (Swift / Kotlin / Flutter / React Native)

Mobile apps leak debug doors too — logging that ships in the release binary, debug flags hard-coded on, and dev menus left enabled.

```bash
# iOS / Swift: print/NSLog left in, or a debug flag forced on
grep -rEn --include='*.swift' \
  -e 'print\(' \
  -e 'NSLog\(' \
  -e 'isDebug\s*=\s*true' \
  -e 'UserDefaults.*debug' \
  . 2>/dev/null

# Android / Kotlin / Java: debuggable flag, verbose logging in release
grep -rEn --include='*.kt' --include='*.java' --include='*.gradle*' --include='AndroidManifest.xml' \
  -e 'android:debuggable\s*=\s*"true"' \
  -e 'debuggable\s+true' \
  -e 'Log\.(d|v)\(' \
  -e 'StrictMode' \
  . 2>/dev/null

# Flutter / Dart: debug prints, debug banner, or asserts shipping logic
grep -rEn --include='*.dart' \
  -e 'debugPrint\(' \
  -e 'print\(' \
  -e 'kDebugMode' \
  -e 'debugShowCheckedModeBanner\s*:\s*true' \
  . 2>/dev/null

# React Native: __DEV__ logic shipped, console left in, dev menu
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules} \
  -e 'console\.(log|debug)\(' \
  -e '__DEV__' \
  -e 'enableHermesDevTools|DevSettings' \
  . 2>/dev/null
```

## The dangerous patterns

**Pattern 1: Django/Flask debug page (CRITICAL)**

```python
# settings.py
DEBUG = True   # ← shipped to prod
```

When any unhandled exception hits this app in production, Django renders its yellow debug page. That page shows: the full stack trace, every local variable's value at the crash site, your installed apps, and — at the bottom — a dump of your *entire settings object*, including `SECRET_KEY`, database credentials, and any API keys you loaded into settings. An attacker doesn't need to "hack" anything; they just need to make your app throw one error (send a malformed request, hit a route with bad input) and read the page. Flask's Werkzeug debugger is worse: it gives an *interactive Python console* in the browser at the crash point.

**Pattern 2: Spring Actuator wide open (CRITICAL)**

```properties
management.endpoints.web.exposure.include=*
```

`GET /actuator/env` returns your full resolved configuration — including secrets pulled from environment variables. `GET /actuator/heapdump` downloads a snapshot of live application memory (session tokens, in-flight passwords). These are reachable with no auth unless you added Spring Security and configured it. Whole companies have been breached through `/actuator/env`.

**Pattern 3: GraphQL introspection / Swagger in prod (HIGH)**

```js
const server = new ApolloServer({ schema, introspection: true });  // ← prod
```

```python
app = FastAPI()  # ← /docs and /redoc are LIVE on the public URL
```

Introspection and Swagger hand an attacker a complete, machine-readable map of every query, mutation, endpoint, parameter, and type your API has — including the internal admin ones you forgot to lock down. It turns "find the hidden endpoints" (hours of guessing) into "read the menu" (one request). It's not a breach by itself, but it's the reconnaissance step that makes every *other* hole trivial to find.

**Pattern 4: An admin DB tool published next to your app (CRITICAL)**

```yaml
# docker-compose.yml
services:
  adminer:
    image: adminer
    ports:
      - "8080:8080"   # ← reachable on your server's public IP
```

Adminer is a full database admin panel. If port 8080 is published and your server has a public IP, anyone who finds it can attempt to log into your database from a web form. Grafana and pgAdmin ship with default credentials (`admin`/`admin`) that nobody changes. This is "left the back door of the warehouse open with a sign pointing to it."

**Pattern 5: Source maps in the deploy folder (MEDIUM)**

```
dist/assets/index-a1b2c3.js
dist/assets/index-a1b2c3.js.map   ← ships your original, commented source
```

A `.js.map` file lets anyone reconstruct your *original* source code — variable names, comments, internal logic, and any secret you mistakenly put in client code — straight from the browser's dev tools. It doesn't directly break anything, but it removes all the friction from understanding (and attacking) your front end, and it often reveals hard-coded keys you thought were "buried" in the bundle.

## Safe patterns

Tie every debug door to the environment, defaulting to OFF:

```python
# Django settings.py
import os
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"  # off unless explicitly set
```

```python
# FastAPI — explicitly disable the explorers in prod
import os
is_prod = os.environ.get("APP_ENV") == "production"
app = FastAPI(
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json",
)
```

```js
// Apollo — introspection off in prod
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== "production",
});
```

```properties
# Spring — expose only what you actually need, and lock it down
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when-authorized
```

Admin tools belong on a private network, never with a published host port:

```yaml
# docker-compose.yml — adminer reachable only inside the compose network,
# and only when you opt into the "tools" profile
services:
  adminer:
    image: adminer
    profiles: ["tools"]   # not started by default
    # no `ports:` block → not published to the host
```

## Report a finding as

**Title:** "Your app's debug mode is on — one error spills your secrets to anyone"

(use this title for Pattern 1; adapt for the others)

**Detail:**
> `settings.py:18` has `DEBUG = True`, and your `.env` shows `DJANGO_DEBUG` isn't set to flip it off in production. This is the developer error page — the thing that helps you while you build. It should never reach the live site.
>
> **What can go wrong:** A visitor sends one request your app doesn't expect — a weird URL, a form field with the wrong type, anything that throws an error. Instead of a clean "something went wrong" page, Django shows them the full crash page: your stack trace, the values of every variable at the moment it broke, and a dump of your settings — which includes `SECRET_KEY` and your database password. They didn't break in. You handed them the keys on an error page. A bot scanning the internet for `DEBUG=True` Django sites will find yours within days of launch.
>
> **How to fix tonight (5 minutes):**
> 1. Make debug default to OFF and only turn on when you explicitly ask:
>    ```python
>    import os
>    DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
>    ```
> 2. In your production environment (Vercel/Render/Railway/your host's dashboard), make sure `DJANGO_DEBUG` is either unset or `false`. Don't set it to `true` anywhere except your own laptop.
> 3. Set `ALLOWED_HOSTS` to your real domain so the app refuses stray requests.
> 4. Verify after deploy: visit a URL that doesn't exist on your live site (`yourapp.com/this-does-not-exist`). You should get a plain 404 — *not* a detailed error page. If you see code or variable values, debug is still on.
>
> Same idea for the others if found: introspection/Swagger off in prod, Actuator narrowed to `health,info`, admin DB tools un-published from the host, and `GENERATE_SOURCEMAP=false` for your production build.

Repeat the report block for each open door you found — they're independent doors, list each one.

## Don't false-positive on

- **Debug flags that are already env-gated.** `DEBUG = os.environ.get("DEBUG") == "1"`, `introspection: process.env.NODE_ENV !== "production"`, `debuggable false` in the release build type — these are the *correct* pattern. Not a finding. Only flag when the flag is hard-coded `True`/`true`, or defaults to on.
- **`.map` files inside `node_modules/`, `vendor/`, or a dependency's own dist.** Those are the library authors' maps, not your source. Only flag maps generated from *your* code in *your* build output.
- **Swagger / GraphQL playground that's clearly behind auth or an `if (dev)` guard.** If the mount is wrapped in `if (process.env.NODE_ENV === 'development')` or sits behind an admin auth check, it's fine.
- **Internal-only tooling repos.** If this is plainly a local dev harness, an internal admin tool, or a `docker-compose.yml` meant for a developer's machine (no public deploy, bound to `127.0.0.1`), the doors being open is expected. Note as INFO, mention it, don't alarm.
- **Ports bound to localhost.** `127.0.0.1:8080:8080` (note the IP prefix) publishes the admin tool only to the host machine, not the public internet. That's much safer than a bare `8080:8080`. Downgrade to LOW/INFO.
- **`print()` / `console.log` / `Log.d` in build scripts, tests, or CLI tools.** Logging in a one-off script or a test file isn't a shipped-to-users leak. Only flag logging that runs inside the production app/binary path — and even then it's usually LOW unless it's printing secrets or PII.
- **`debug`-named npm packages or the `debug()` logger.** The popular `debug` library is namespaced and off by default (controlled by the `DEBUG` env var at runtime). Its mere presence in `package.json` is not a finding.
- **Health/info actuator endpoints only.** `exposure.include=health,info` is the safe, intended config. Not a finding.
