# Registro de trazabilidad - Sistema Alumnos

Cada fila la agrega Jenkins al terminar un build (`scripts/trazabilidad.py`).

| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-27 20:23 | 1.0.1+a55897c | `a55897c` | Proyecto incial: Sistema alumnos (codigo vulnerable) | 9/9 OK | n/a | n/a | n/a | SUCCESS | 1.0.1+a55897c |
| 2 | 2026-11-27 21:02 | 1.0.2+c697168 | `c697168` | DEP: configurar Dependabot para dependencias de Python | 9/9 OK | 2/2/1 | 20 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 3 | 2026-11-27 21:05 | 1.0.3+c697168 | `c697168` | DEP: configurar Dependabot para dependencias de Python | 9/9 OK | 2/2/1 | 20 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 4 | 2026-11-27 21:45 | 1.0.4+e8fa6b5 | `e8fa6b5` | VULN-04: secretos desde el entorno y hash seguro de la clave admin | 9/9 OK | 0/0/0 | 20 vuln. | 0/3/1 | UNSTABLE | no desplegado |
| 5 | 2026-11-27 21:56 | 1.0.5+50b1d92 | `50b1d92` | VULN-07: cabeceras de seguridad HTTP | 9/9 OK | 0/0/0 | 20 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 6 | 2026-11-27 22:08 | 1.0.6+3acfe5b | `3acfe5b` | Merge pull request #1 from AydanGM/dependabot/pip/dependencias-python- | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.6+3acfe5b |
