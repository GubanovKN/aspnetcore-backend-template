# ASP .NET Core Backend Template
<span style="color:red">WARNING: Template in development</span>
## Current tasks
- [x] Confirm email
- [x] Confirm phone
- [x] Login by phone with code
- [x] Login by email with code
- [x] Login by email with password
- [x] OAuth
- [x] Forgot Password
- [x] Tests
- [x] Refresh time expire key in cache
- [ ] Change user info

Additional tasks will be added in the future

## Setup
Use cookiecutter for first config
```cookiecutter https://github.com/GubanovKN/aspnetcore-backend-template.git```

## Docker compose depends
```
version: '3.9'
services:
  db:
    image: postgres:13.1
    container_name: postgres_provider
    environment:
      - POSTGRES_USER=root
      - POSTGRES_PASSWORD=root
    ports:
      - "45432:5432"
    networks:
      - depends_network
    restart: always
    volumes:
       - ./postgres-data:/var/lib/postgresql/data
  cache:
    image: redis/redis-stack-server:latest
    container_name: redis_provider
    restart: always
    ports:
      - "46379:6379"
    volumes:
      - ./redis-data:/var/lib/redis
    environment:
      - REDIS_REPLICATION_MODE=master
      - REDIS_ARGS=--save 20 1 --loglevel warning --requirepass root
    networks:
      - depends_network
  nginx-proxy-manager:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '443:443'
      - '81:81'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
    networks:
      - depends_network
  npm-monitoring:
    image: xavierh/goaccess-for-nginxproxymanager:latest
    restart: always
    environment:
        - TZ=Asia/Yekaterinburg
        - SKIP_ARCHIVED_LOGS=True
        - EXCLUDE_IPS=127.0.0.1
        - LOG_TYPE=NPM
    ports:
        - '82:7880'
    volumes:
        - ./data/logs:/opt/log
    networks:
      - depends_network
networks:
  depends_network:
    name: depends_network
    driver: bridge
```
### Important in production
  - The database port and cache port is open, it is better to remove this option
  - The database user, password and cache password change to custom
### Connection strings
  - PostgreSQL "Host={host};Port={port};Database={name_db};Username={user_name};Password={user_pass}"
  - Redis "{host}:{port},password={pass},DefaultDatabase={db_number}" or "redis://{user_name}:{user_pass}@{host}:{port}/{db_number}" (Default user - default)
## Google OAuth
  1. When you configure solution, in main path exist file check-oauth.html
  2. Open in browser this file and click button "Sign in with Google"
  3. After login in Google you will redirect in config page with more get params
  4. Then copy "code" parameter and paste in swagger body request users/authenticate-google
#### Parameter "code" maybe in URL Encode, should decode before paste in body request
## Tests
  Repos has file api.postman_collection.json, import this file to Postman for test routes
## Docker build
  Integrate image in {project_name}/api/Dockerfile in your docker compose
  Also you can build image
  ```docker build -t {image_name} "./{project_name}/api"```
