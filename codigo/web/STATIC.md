# web/static

Archivos que el programa sirve tal cual (van dentro del binario con `go:embed`).
No se cargan de internet: el panel funciona aunque se caiga el internet.

| Archivo | Origen | Versión | SHA-256 |
| :--- | :--- | :--- | :--- |
| `htmx.min.js` | https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js (igual a unpkg) | 2.0.6 | `b6768eed4f3af85b73a75054701bd60e17cac718aef2b7f6b254e5e0e2045616` |

Para actualizar htmx: bajar la versión nueva de dos CDN, comprobar que sean idénticas, reemplazar el
archivo y actualizar esta tabla.

Configuración de htmx en las páginas (CSP estricta, sin `unsafe-eval` ni estilos en línea):

    <meta name="htmx-config" content='{"allowEval":false,"allowScriptTags":false,"includeIndicatorStyles":false}'>
