<div align="center">

```
 ██████╗ ███████╗██╗   ██╗ ██╗ ██████╗  ██╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║███║██╔═████╗███║╚██╗██╔╝
██║  ██║█████╗  ██║   ██║╚██║██║██╔██║╚██║ ╚███╔╝
██║  ██║██╔══╝  ╚██╗ ██╔╝ ██║████╔╝██║ ██║ ██╔██╗
██████╔╝███████╗ ╚████╔╝  ██║╚██████╔╝ ██║██╔╝ ██╗
╚═════╝ ╚══════╝  ╚═══╝   ╚═╝ ╚═════╝  ╚═╝╚═╝  ╚═╝
```

# 🛡️ BUG BOUNTY LAB — dev101x

### **Laboratorio de Caza de Vulnerabilidades para HackerOne**

[![HackerOne](https://img.shields.io/badge/HackerOne-dev101x-000000?style=for-the-badge&logo=hackerone&logoColor=white)](https://hackerone.com/)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Tools](https://img.shields.io/badge/400%2B-Tools-FF6B35?style=for-the-badge)]()
[![Scope Safe](https://img.shields.io/badge/Scope-Enforced-00CA4E?style=for-the-badge)]()

</div>

---

## 🎯 ¿QUÉ ES?

Un lab centrado en el **flujo de trabajo real de bug bounty en HackerOne**:
elegir programa, documentar scope, escanear sin salirse de los límites,
encadenar hallazgos y reportar de forma que un triager lo acepte rápido. El
arsenal de 400+ herramientas de pentesting genérico y el lab de VMs locales
siguen disponibles, pero como soporte — no como punto de entrada.

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  SCOPE                RECON/VULN              REPORTE               │
│  ═════                ══════════              ═══════               │
│                                                                     │
│  ┌───────────┐      ┌───────────────────┐    ┌───────────────┐      │
│  │programs/  │───▶    bugbounty-hunter  ───▶  report.md     
│  │*.md       │      │      .sh          │    │ (H1 template) │      │
│  └───────────┘      └────────┬──────────┘    └───────┬───────┘      │
│  scope check                 │                       │              │
│  (bloquea si no              ▼                       ▼              │
│   está documentado) ┌─────────────┐         ┌──────────────┐        │
│                     │auto-scanner │         │  Hacktivity  │        │
│                     │ (arsenal)   │         │  dedup check │        │
│                     └─────────────┘         └──────────────┘        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ INICIO RÁPIDO (bug bounty real)

### 1. Permisos
```bash
cd /root/vscode/systems/promt/pentesting-lab
chmod +x bugbounty/*.sh auto-scanner/*.sh
```

### 2. Documentar el scope del programa
```bash
cd bugbounty
./bugbounty-hunter.sh new nombre-programa
# Editar ../programs/nombre-programa.md con el scope EXACTO de la política H1
```

### 3. Verificar scope y escanear
```bash
./bugbounty-hunter.sh scope target.com     # debe decir "Scope OK" antes de seguir
./bugbounty-hunter.sh full target.com       # recon -> vuln -> brute -> secrets -> api -> reporte
```

### 4. Reportar
```bash
./bugbounty-hunter.sh report target.com
# Completar bugbounty/reports/target.com/report-YYYYMMDD.md con el template de H1
```

Antes de enviar, lee [`docs/hackerone-workflow.md`](docs/hackerone-workflow.md)
(dedup en Hacktivity, calidad de reporte, qué hacer post-envío).

---

## 🚀 COMANDOS PRINCIPALES

<div align="center">

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `bugbounty-hunter.sh new <prog>` | 📋 Crear scope tracker de un programa | `./bugbounty-hunter.sh new acme-corp` |
| `bugbounty-hunter.sh scope <target>` | 🛑 Verificar que un target está en scope | `./bugbounty-hunter.sh scope target.com` |
| `bugbounty-hunter.sh full <target>` | 🔍 Pipeline completo (recon→reporte) | `./bugbounty-hunter.sh full target.com` |
| `bugbounty-hunter.sh recon <target>` | 🕵️ Solo reconocimiento | `./bugbounty-hunter.sh recon target.com` |
| `bugbounty-hunter.sh report <target>` | 📝 Generar reporte con template H1 | `./bugbounty-hunter.sh report target.com` |
| `pentest.sh <url>` | 🛠️ Arsenal genérico completo (400+ tools) | `pentest.sh https://target.com` |
| `pentest.sh matrix` | 🗺️ Matriz completa de herramientas | `pentest.sh matrix` |
| `pentest.sh search <función>` | 🔎 Buscar herramienta en el arsenal | `pentest.sh search sql_injection` |
| `pentest.sh express <url>` | ⚡ Escaneo express con el arsenal | `pentest.sh express https://target.com` |
| `pentest.sh install` | 📥 Instalar herramientas que falten | `pentest.sh install` |

</div>

Todos los comandos de escaneo activo de `bugbounty-hunter.sh` verifican scope
automáticamente contra `programs/*.md` antes de tocar el target.

---

## 🗺️ MATRIZ DE HERRAMIENTAS POR FASE

```
╔═════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║  FASE 1            FASE 2            FASE 3            FASE 4           ║
║  RECONOCIMIENTO    ESCANEO           ENUMERACIÓN       EXPLOTACIÓN      ║
║                                                                         ║
║  ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐    ║
║  │   nmap    │───▶    nikto     ───▶│  enum4l   │───▶  sqlmap         
║  │   amass   │     │ gobuster  │     │  smbclnt  │     │metasploit │    ║
║  │   dig     │     │  whatweb  │     │  ldapsrc  │     │  xsser    │    ║
║  │   whois   │     │   wfuzz   │     │  rpcclnt  │     │  wpscan   │    ║
║  └───────────┘     └───────────┘     └───────────┘     └───────────┘    ║
║        │                │                │                │             ║
║        ▼                ▼                ▼                ▼             ║
║  ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐    ║
║  │  theHarv  │     │   dirb    │     │ snmpwalk  │     │ msfvenom  │    ║
║  │  recon-ng │     │   ffuf    │     │  nbtscan  │     │ searchsp  │    ║
║  └───────────┘     └───────────┘     └───────────┘     └───────────┘    ║
║                                                                         ║
╠═════════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║  FASE 5            FASE 6            FASE 7            FASE 8           ║
║  BUSINESS LOGIC    API TESTING       CHAIN ATTACKS     REPORTE          ║
║                                                                         ║
║  ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐    ║
║  │auth flow  │     │  swagger  │     │CORS+CSRF  │     │    H1     │    ║
║  │race cond  │     │  graphql  │     │SSRF+RCE   │     │  REPORT   │    ║
║  │mass assn  │     │  nuclei   │     │IDOR+priv  │     │   .md     │    ║
║  └───────────┘     └───────────┘     └───────────┘     └───────────┘    ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
```

---

## 📦 HERRAMIENTAS POR CATEGORÍA (auto-scanner/ — arsenal de soporte)

<div align="center">

### 🔍 RECONOCIMIENTO (50+ herramientas)

```
┌────────────────────────────────────────────────────────────────┐
│  NETWORK SCANNING:                                             │
│  nmap        masscan      zmap         unicornscan             │
│  netdiscover                                                   │
│                                                                │
│  DNS ENUMERATION:                                              │
│  dnsrecon    dig          host         dnsenum                 │
│  dnsmap      sublist3r    subfinder    subbrute                │
│  dnsgen      gotator      fierce       dnspoodle               │
│                                                                │
│  HTTP RECON:                                                   │
│  httpx       httprobe     gau          waybackurls             │
│  katana      gospider     hakrawler    linkfinder              │
│  jsfinder    secretfinder paramspider  arjun                   │
│                                                                │
│  CLOUD RECON:                                                  │
│  s3scanner   cloud_enum   lazys3       bucket_finder           │
│                                                                │
│  SUBDOMAIN TAKEOVER:                                           │
│  subjack     subover      nuclei       canari                  │
└────────────────────────────────────────────────────────────────┘
```

### 🌐 WEB (20+ herramientas)

```
┌─────────────────────────────────────────────────────────────────┐
│  SCANNERS:        nikto  whatweb  wapiti  arachni  skipfish     │
│  DIRECTORY BRUTE: gobuster  dirb  feroxbuster  dirsearch        │
│  FUZZING:         wfuzz  ffuf  arjun  x8  paramspider           │
│  VULNERABILITIES: sqlmap  xsser  dalfox  commix  xsstrike       │
│  CMS:             wpscan  joomscan  droopescan  cmseek  cariddi │
└─────────────────────────────────────────────────────────────────┘
```

</div>

---

## 📈 EJEMPLO DE REPORTE (formato HackerOne)

```markdown
# Bug Bounty Report

## Platform
HackerOne

## Program
[nombre del programa]

## Researcher
dev101x

## Target
prime.example.com

## Weakness (H1 taxonomy)
CWE-538: Insertion of Sensitive Information into Externally-Accessible File

## Executive Summary
S3 bucket con listing habilitado expone N archivos sin autenticación,
incluyendo documentos internos de RRHH.

## Steps to Reproduce
1. curl -k https://prime.example.com/file-service/static/
2. ...

## Impact
[Impacto de negocio concreto, no genérico]
```

Ver plantilla completa en [`bugbounty/templates/report-template.md`](bugbounty/templates/report-template.md).

---

## 🛡️ FLUJO DE TRABAJO

```
                      ┌─────────────────────┐
                      │  Elegir programa H1 │
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │ bugbounty-hunter.sh │
                      │   new <programa>    │
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │ Documentar scope en │
                      │   programs/*.md     │
                      └──────────┬──────────┘
                                 ▼
                ┌────────────────────────────────┐
                │ bugbounty-hunter.sh full <t>   │
                └────────────────┬───────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
       │ RECON/VULN   │   │ MANUAL VERIF │   │ CHAIN ATTACK │
       │  (scripts)   │   │  (a mano)    │   │  (a mano)    │
       └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
              └──────────────────┼──────────────────┘
                                 ▼
                      ┌─────────────────────┐
                      │ Dedup en Hacktivity │
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │  Enviar reporte H1  │
                      └─────────────────────┘
```

Ver metodología completa en [`docs/hackerone-workflow.md`](docs/hackerone-workflow.md).

---

## 💾 PRACTICAR SIN TOCAR UN PROGRAMA REAL

`legacy-vm-practice/` es tuyo: IPs privadas que tú levantas, sin scope de
terceros que respetar. Úsalo para aprender técnicas nuevas antes de aplicarlas
en un programa real.

```bash
cd legacy-vm-practice
./scripts/setup_network.sh   # requiere sudo
./scripts/download_vms.sh
./scripts/start_lab.sh
./scripts/verify_lab.sh
```

Ver `legacy-vm-practice/README.md` y `legacy-vm-practice/docs/quickstart.md`.

---

## 📁 ESTRUCTURA DEL PROYECTO

```
pentesting-lab/
│
├── 📄 README.md                    # Este archivo — overview + guía de uso
│
├── 📂 programs/                    # 📋 Scope tracker: un .md por programa H1
│   ├── 📄 README.md
│   └── 📄 _template.md
│
├── 📂 bugbounty/                   # 🎯 Motor principal de bug bounty
│   ├── 📄 bugbounty-hunter.sh      # scope/new/recon/vuln/brute/secrets/api/report
│   ├── 📄 QUICK-REFERENCE.md       # Comandos, payloads, bounty por severidad
│   ├── 📂 templates/report-template.md
│   └── 📂 reports/<target>/        # Salida de cada fase + reporte final
│
├── 📂 auto-scanner/                # 🤖 Arsenal genérico (400+ tools, no H1-específico)
│   ├── 📄 pentest.sh               # Comando unificado (incl. `pentest.sh bounty ...`)
│   ├── 📂 tools/registry.sh
│   ├── 📂 burp-integration/
│   └── 📂 reports/
│
├── 📂 docs/
│   ├── 📄 hackerone-workflow.md    # Metodología H1: elegir programa, dedup, calidad
│   ├── 📄 ai-assisted-code-review.md  # Revisión de código/JS asistida por AI
│   ├── 📄 known-cve-watchlist.md   # CVEs más reportados en Hacktivity
│   ├── 📄 known-cwe-watchlist.md   # Clases de vuln más reportadas en Hacktivity
│   └── 📂 recursos/learning-resources.md
│
└── 📂 legacy-vm-practice/          # 💾 Lab clásico de VMs (DVWA, Metasploitable...)
```

---

## ⚠️ REGLAS IMPORTANTES

1. **Nunca escanees un asset que no esté en `programs/<programa>.md` como In Scope.** `bugbounty-hunter.sh` lo bloquea por defecto — `FORCE=1` es una señal de que falta documentar el scope, no un atajo normal.
2. **Respeta las exclusiones y reglas especiales de cada programa** (rate limits, tipos de vuln excluidos, cuentas de prueba).
3. **Busca duplicados en Hacktivity antes de reportar.**
4. **No ejecutes acciones destructivas** contra targets reales — ver el checklist en `bugbounty/templates/report-template.md`.
5. **`legacy-vm-practice/` es tuyo**: IPs privadas que tú levantas, sin scope de terceros. Úsalo para aprender técnicas nuevas antes de aplicarlas en un programa.

---

## 🔧 SOLUCIÓN DE PROBLEMAS

**`bugbounty-hunter.sh` dice "No hay archivo de scope"**
Corre `./bugbounty-hunter.sh new <programa>` y agrega el dominio a la sección
`## In Scope` del archivo generado en `programs/`.

**Faltan herramientas (subfinder, nuclei, httpx, etc.)**
```bash
./auto-scanner/pentest.sh install
```

**El lab de VMs no arranca**
Ver troubleshooting en `legacy-vm-practice/README.md` (Host-Only Adapter, NAT, firewall).

---

## 🎓 RECURSOS DE APRENDIZAJE

<div align="center">

| Recurso | Enfoque |
|---------|---------|
| [Hacker101](https://www.hacker101.com/) | CTFs + videos de HackerOne, badges para programas privados |
| [HackerOne Hacktivity](https://hackerone.com/hacktivity) | Reportes públicos — estudiar calidad y evitar duplicados |
| [HackerOne Directory](https://hackerone.com/directory/programs) | Elegir programa por scope y estadísticas de respuesta |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Fundamentos técnicos de vulnerabilidades web |

</div>

Lista completa en [`docs/recursos/learning-resources.md`](docs/recursos/learning-resources.md).

---

## ⚠️ DISCLAIMER

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ⚠️  ADVERTENCIA LEGAL                                                       
║                                                                              ║
║  Este lab está diseñado para bug bounty AUTORIZADO vía HackerOne.            ║
║                                                                              ║
║  • Solo testea assets dentro del scope publicado del programa                ║
║  • bugbounty-hunter.sh bloquea targets sin scope documentado en programs/    ║
║  • El uso no autorizado de estas herramientas es ILEGAL                      ║
║  • Respeta las exclusiones y reglas especiales de cada programa              ║
║  • Usa siempre de manera ÉTICA y RESPONSABLE                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 📊 ESTADÍSTICAS DEL ARSENAL

<div align="center">

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   🔍 RECONOCIMIENTO    200+ herramientas   ████████████████ 100%│
│   📋 ENUMERACIÓN        60+ herramientas   ██████████░░░░░░  60%│
│   🌐 WEB                20+ herramientas   ████░░░░░░░░░░░░  20%│
│   💥 EXPLOTACIÓN        80+ herramientas   ████████████████  80%│
│   🔧 POST-EXPLOIT       50+ herramientas   ████████████░░░░  60%│
│                                                                 │
│   TOTAL: 400+ herramientas categorizadas                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

</div>

---

<div align="center">

```
+=============================================================+
|                                                              |
|   dev101x  •  HackerOne Bug Bounty  •  400+ Tools            |
|                                                              |
+=============================================================+
```

**Happy hunting.** 🎯

</div>
