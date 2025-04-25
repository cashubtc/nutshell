## Docker compose

This docker-compose starts a new keycloak instance. Set up the server as you wish, add realms, users etc. We will then export the data and restore an instance with the exported data.

We will modify this file later to start the server with the backup data.

```
services:
  postgres:
    image: postgres:16.4
    volumes:
      - ./postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    networks:
      - keycloak_network

  keycloak:
    image: quay.io/keycloak/keycloak:25.0.6
    command: start
    environment:
      KC_HOSTNAME: localhost
      KC_HOSTNAME_PORT: 8080
      KC_HOSTNAME_STRICT_BACKCHANNEL: false
      KC_HTTP_ENABLED: true
      KC_HOSTNAME_STRICT_HTTPS: false
      KC_HEALTH_ENABLED: true
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres/${POSTGRES_DB}
      KC_DB_USERNAME: ${POSTGRES_USER}
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - 8080:8080
    restart: always
    depends_on:
      - postgres
    networks:
      - keycloak_network

volumes:
  postgres_data:
    driver: local

networks:
  keycloak_network:
    driver: bridge
```

## Backup

Export realm and users from running container:

```
docker exec keycloak-keycloak-1 \
  /opt/keycloak/bin/kc.sh export \
  --dir /opt/keycloak/data/export \
  --users different_files \
  --http-management-port 46566
```

Copy export out of the docker

```
docker cp keycloak-keycloak-1:/opt/keycloak/data/export ./keycloak-export
```

## Restore

Use this docker-compose.yml to start keycloak with the exported backup:

```
services:
  postgres:
    image: postgres:16.4
    volumes:
      - ./postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    networks:
      - keycloak_network

  keycloak:
    image: quay.io/keycloak/keycloak:25.0.6
    command: start --import-realm
    volumes:
      - ./keycloak-export:/opt/keycloak/data/import
    environment:
      KC_HOSTNAME: localhost
      KC_HOSTNAME_PORT: 8080
      KC_HOSTNAME_STRICT_BACKCHANNEL: false
      KC_HTTP_ENABLED: true
      KC_HOSTNAME_STRICT_HTTPS: false
      KC_HEALTH_ENABLED: true
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres/${POSTGRES_DB}
      KC_DB_USERNAME: ${POSTGRES_USER}
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - 8080:8080
    restart: always
    depends_on:
      - postgres
    networks:
      - keycloak_network

volumes:
  postgres_data:
    driver: local

networks:
  keycloak_network:
    driver: bridge
```

Difference to first docker-compose is only the following part:

```
    command: start --import-realm
    volumes:
      - ./keycloak-export:/opt/keycloak/data/import
```
