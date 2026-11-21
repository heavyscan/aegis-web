# Aegis Web Console

Plataforma web modular, independente e estritamente **defensiva/passiva** para diagnóstico HTTP, auditoria de hardening OWASP, validação de contratos OpenAPI/JSON Schema, postura TLS/DNS e utilitários de Web QA com suporte opcional a IA local (**Ollama**).

## Recursos Principais

- **Motor Plugável com 30 Módulos Defensivos sob Demanda:** apenas os módulos marcados como ativos são executados em cada inspeção passiva (`GET`, `HEAD` ou `OPTIONS`), reduzindo uso de CPU e memória.
- **Auditoria Completa de Hardening & OWASP:**
  - Parser detalhado de **CSP** (`Content-Security-Policy` e `Report-Only`), **HSTS** (`max-age`, `includeSubDomains`, `preload`), **Clickjacking** (`X-Frame-Options` / `frame-ancestors`), **CORS** (`ACAO`, `ACAC`, `Vary: Origin`), **Cross-Origin Isolation** (`COOP`, `COEP`, `CORP`), **Rate-Limit** (`RateLimit-*` / `Retry-After`) e **Cache-Control / CDN**.
  - **TLS & Certificados:** protocolo negociado (`TLSv1.3` / `TLSv1.2`), força de cifra AEAD, CN, emissor, SANs e dias até expiração.
  - **Postura DNS Passiva:** verificação de registros públicos `CAA`, `SPF` e `DMARC`.
  - **Sessão, Privacidade & HTML:** auditoria de cookies (`Secure`, `HttpOnly`, `SameSite`, prefixos `__Host-`/`__Secure-`), entropia de Shannon de tokens, detecção passiva de exposição de stack/segredos, SRI e mixed-content em scripts, links `target="_blank"` sem `rel="noopener noreferrer"` e iframes sem `sandbox`.
  - **Contratos de API:** validação passiva de JSON + `nosniff` + `charset=utf-8` e auditoria de especificações **OpenAPI 3.x / Swagger 2.0**.
  - **Nota OWASP (`0–100` / `A–F`)** + geração automática de **snippets de hardening** prontos para **Nginx**, **Apache** e **Express.js**.
- **Bancada Web QA Integrada:**
  - Decoder / Encoder (`Base64`, `URL`, `HTML`, `Hex`, `SHA-256` e **JWT Inspector**)
  - Response & Text Comparer linha a linha (integrado ao histórico)
  - Calculador de Entropia de Shannon para tokens
  - Decompositor de URL (URL Parser)
  - **Validador OpenAPI 3.x & JSON Schema**
  - **Auditor Offline & Construtor de Políticas CSP / Security Headers**
- **Orquestração por Presets ou IA Local (Ollama):** presets `essential`, `api-qa`, `compliance-full`, `all-on` e `all-off`, além de seleção automática do subconjunto mínimo de módulos e resumo defensivo via Ollama local.
- **Relatórios Personalizáveis:** exportação em **PDF 1.4**, **HTML estilizado para impressão**, **Markdown (`.md`)** e **JSON**, com título, organização, classificação, filtro de severidade mínima e inclusão opcional de módulos, snippets de hardening e cabeçalhos HTTP.

## Instalação e Execução

Requisitos: **Node.js 18+**.

```bash
npm install
npm start
```

Por padrão, o servidor sobe na porta `3002` (configurável via variável de ambiente `PORT`):

```bash
PORT=3002 node webserver.js
```

Acesse `http://127.0.0.1:3002` no navegador.

## Principais Endpoints REST

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Estado geral, modo ativo, módulos e última nota OWASP |
| `POST` | `/api/mode` | Alterna modo padrão (`manual` ou `ai-automation`) |
| `GET` | `/api/modules` | Lista os 30 módulos defensivos e estatísticas por categoria |
| `POST` | `/api/modules/:id` | Ativa, desativa ou alterna um módulo individual |
| `POST` | `/api/modules/bulk` | Aplica preset (`essential`, `api-qa`, `compliance-full`, `all-on`, `all-off`) |
| `POST` | `/api/inspect/run` | Executa inspeção HTTP/TLS/DNS passiva com os módulos ativos |
| `GET` / `DELETE` | `/api/inspect/history` | Consulta ou limpa o histórico da sessão |
| `GET` | `/api/inventory` | Inventário consolidado de hosts inspecionados |
| `POST` | `/api/qa/validate-schema` | Valida JSON contra JSON Schema ou audita OpenAPI 3.x |
| `POST` | `/api/qa/audit-csp` | Audita diretivas de um cabeçalho CSP offline |
| `GET` / `POST` | `/api/ai/config` | Consulta ou salva configuração do provedor local Ollama |
| `POST` | `/api/ai/recommend-modules` | Recomenda e aplica subconjunto enxuto de módulos |
| `POST` | `/api/ai/chat` | Consulta defensiva à IA local |
| `GET` | `/api/report` | Exporta relatório personalizado (`format=pdf\|html\|md\|json`) |

## Estrutura do Projeto

- `webserver.js` — Servidor Express, coleta passiva HTTP/TLS/DNS, API REST e geradores de relatórios (`PDF`, `HTML`, `MD`, `JSON`).
- `module_engine.js` — Motor modular executável dos 30 verificadores defensivos, validador OpenAPI/JSON Schema, auditor CSP e gerador de snippets de hardening.
- `modules.json` — Catálogo persistente e estado de ativação dos 30 módulos.
- `index.html` — Interface web single-page (sem dependências externas de CDN).
- `ai_config.json` — Configuração do endpoint/modelo local do Ollama.

## Licença

Distribuído sob a licença MIT. Consulte [LICENSE](LICENSE).
