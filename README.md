# ASP .NET Core Backend Template
<span style="color:red">WARNING: Template in development</span>
## Current tasks
- [ ] Confirm email
- [ ] Confirm phone
- [ ] Login by phone with code
- [ ] Login by email with code
- [ ] Login by email with password
- [ ] OAuth

Additional tasks will be added in the future

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
  redis:
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
### Important
  - The database port is open, it is better to remove this option when creating a working version
