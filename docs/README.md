# NetLens – Fase 1

Fundaciones del monorepo y primer módulo de resolución IP.

- Core desacoplado en `packages/core/` con:
  - `normalize_url(url) -> (host, port)`: agrega esquema por defecto (http) y determina el puerto (80/443 o explícito).
  - `resolve_ip(host) -> ip`: resuelve IPv4 vía `socket.gethostbyname`.
- Apps:
  - CLI (`apps/cli/main.py`): `--name` y `--url` → imprime `name, ip, port`.
  - GUI mínima Tkinter (`apps/gui/main.py`): campos Nombre y URL, botón que muestra `nombre, ip, puerto`.
  - API Flask (`apps/api/main.py`): `POST /resolve` con JSON `{name, url}` y responde `{name, ip, port}`.
- Tests (`tests/test_core.py`) con pytest validando `normalize_url` y `resolve_ip`.

Para ejecutar tests:

```
pytest -q
```

