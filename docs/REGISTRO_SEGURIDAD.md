# Registro de seguridad · Sistema Alumnos

Estudiante: Aydan González   Repositorio: https://github.com/AydanGM/sistema-alumnos-ev3   Fecha: 27-11-2026

Completa este registro a medida que avanzas. Cada fila debe poder seguirse hasta un **build de Jenkins**
y un **commit** (usa el identificador `VULN-xx` en el mensaje del commit).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline | #2 | 2 hallazgos High / 2 Medium / 1 Low (después de VULN-04: 0/0/0, build #3) |
| R2 | Dependencias (SCA) | pip-audit en el pipeline | #2 | 20 vulnerabilidades en 5 paquetes (después del PR de Dependabot: 0, build #5) |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP sobre staging | #2 | 1 High / 3 Medium / 1 Low (después de VULN-07: 0/0/0, build #4) |
| R4 | Revisión manual | Lectura de `app.py` | — | Inyección SQL en `/alumnos/buscar`, clave del admin en MD5 (`admin`), login sin límite de intentos, `debug=True` |
| R5 | Producción | Grafana + Prometheus | — | Se detectó un ataque de fuerza bruta e inyección (ver sección 4) |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL (CWE-89) | Bandit B608, revisión manual, simular_ataque | `app.py:205` | Alto | Consulta parametrizada (`LIKE ?`) y error sin detalles | `VULN-01` | #3 |
| VULN-02 | XSS reflejado (CWE-79) | OWASP ZAP (High), simular_ataque | `app.py:154` | Alto | `escape()` del parámetro `name` | `VULN-02` | #3 |
| VULN-03 | Modo debug activo (CWE-489) | Bandit B201, B104 | `app.py:241` | Alto | `debug=False` y `host="127.0.0.1"` | `VULN-03` | #3 |
| VULN-04 | Clave en el código y MD5 (CWE-798, CWE-328) | Bandit B105, B324, simular_ataque | `app.py:20-22, 221` | Crítico | `SECRET_KEY` y hash del admin desde variables de entorno; `check_password_hash` en vez de MD5 | `VULN-04` | #3 |
| VULN-05 | Sin límite de intentos de login (CWE-307) | simular_ataque, Grafana | `app.py:214` | Alto | 5 intentos fallidos por IP → HTTP 429 | `VULN-05` | #4 |
| VULN-06 | Sin token anti-CSRF (CWE-352) | OWASP ZAP (Medium) | `app.py:69, 214` | Medio | Token en la sesión y en el formulario; cookie `SameSite=Lax` | `VULN-06` | #4 |
| VULN-07 | Faltan cabeceras de seguridad (CWE-693) | OWASP ZAP (2 Medium, 1 Low) | `app.py:125` | Medio | `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` | `VULN-07` | #4 |
| VULN-08 | Dependencias vulnerables (CWE-1395) | pip-audit, Dependabot | `requirements*.txt` | Alto | PR de Dependabot (sección 5) | PR #__ | #5 |

## 3. Resultados de OWASP ZAP

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| Cross Site Scripting (Reflected) | High | `/hello?name=...<scrIpt>alert(1);</scRipt>` | VULN-02 | Escapar el parámetro antes de mostrarlo | Sí · #3 |
| Absence of Anti-CSRF Tokens | Medium | `/` | VULN-06 | Token anti-CSRF en el formulario de login | Sí · #4 |
| Content Security Policy (CSP) Header Not Set | Medium | `/` | VULN-07 | Cabecera `Content-Security-Policy` | Sí · #4 |
| Missing Anti-clickjacking Header | Medium | `/` | VULN-07 | Cabecera `X-Frame-Options: DENY` | Sí · #4 |
| X-Content-Type-Options Header Missing | Low | `/alumnos` | VULN-07 | Cabecera `X-Content-Type-Options: nosniff` | Sí · #4 |

## 4. Monitoreo e incidentes

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| __:__ | Logins fallidos por minuto (`login_fallidos_total`) + alerta «Fuerza bruta en login» | Muchos logins fallidos seguidos desde una IP; el atacante encontró la clave `admin` | Producción (1.0.1+_______) | Crítico: acceso no autorizado | VULN-04 (sin clave en el código) y VULN-05 (bloqueo tras 5 intentos); despliegue en build #5 | Ataque repetido: ninguna clave funcionó, __ intentos bloqueados (429) |
| __:__ | Peticiones sospechosas por tipo (`peticiones_sospechosas_total`) | Aumento de `sqli` y `xss`; la inyección mostró la estructura de la base | Producción (1.0.1+_______) | Alto: fuga de información y XSS | VULN-01 y VULN-02; despliegue en build #5 | Ataque repetido: la inyección no devolvió datos y el script quedó escapado |

## 5. Gestión de dependencias

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | CVE-2023-30861, CVE-2026-27205 | 3.1.3 | PR de Dependabot #__ | Sí · #5 |
| Werkzeug | 2.2.2 | 10 (ej. CVE-2023-25577, CVE-2023-46136, CVE-2024-34069) | 3.1.9 | PR de Dependabot #__ | Sí · #5 |
| Jinja2 | 3.1.2 | CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516 | 3.1.6 | PR de Dependabot #__ | Sí · #5 |
| gunicorn | 21.2.0 | CVE-2024-1135, CVE-2024-6827 | 27.0.1 | PR de Dependabot #__ | Sí · #5 |
| prometheus-client | 0.17.1 | Ninguna | 0.26.0 | PR de Dependabot #__ | Sí · #5 |

pytest (requirements-dev.txt) también se actualizó de 8.3.4 a 9.2.0 (CVE-2025-71176) en el mismo PR.

## 6. Trazabilidad

El `TRAZABILIDAD.md` del último build está en `docs/TRAZABILIDAD.md`.

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | MD5, clave en el código, debug, SQL armado con texto | #2 | `VULN-01`, `VULN-03`, `VULN-04` | #3 | 1.0.5+_______ |
| Prueba automatizada (OWASP ZAP) | XSS, sin token anti-CSRF, sin cabeceras | #2 | `VULN-02`, `VULN-06`, `VULN-07` | #4 | 1.0.5+_______ |
| Gestión de dependencias (Dependabot) | 20 vulnerabilidades en 5 paquetes | #2 | PR #__ | #5 | 1.0.5+_______ |
