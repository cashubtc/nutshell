# NUT-19 Response caching

Nutshell caches successful mint, swap, and melt responses in memory by default ([NUT-19](https://github.com/cashubtc/nuts/blob/main/19.md)). A wallet can replay the same request to recover a lost response. Concurrent identical requests within a process share the same operation, which continues if the original caller disconnects. Failed operations are not cached.

## In-memory cache

The local cache holds up to `MINT_MEMORY_CACHE_MAX_ENTRIES` responses (default: 10,000) and `MINT_MEMORY_CACHE_MAX_BYTES` bytes of serialized responses and hashed keys (default: 64 MiB). Python object overhead uses additional memory. Responses expire after `MINT_REDIS_CACHE_TTL` seconds (default: one week); this setting applies to both backends.

The oldest entries can be evicted sooner when either local limit is reached, and an individual response larger than the byte limit is not cached locally. Local responses are lost when the process restarts and are not shared between workers or instances. The advertised TTL does not guarantee recovery after eviction, restart, or a retry routed to another worker.

## Redis

For shared caching across workers or instances, install Redis manually or use the [docker compose file](../docker/redis/docker-compose.yml) to start Redis in a container.

Edit the `.env` file and uncomment the Redis lines:

```bash
MINT_REDIS_CACHE_ENABLED=TRUE
MINT_REDIS_CACHE_URL=redis://localhost:6379
```

When Redis is unavailable at startup or during a request, Nutshell continues with its local cache. Each process retains a bounded local copy of responses it produces, including when a Redis write fails. Responses stored only in Redis or produced by another process cannot be recovered locally during an outage. Redis is tried again on subsequent cache misses; a failed cache write does not fail a successful operation. Concurrent requests across processes still rely on the mint's database transaction checks.
