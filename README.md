# CNABHunter (Nuikita)

## Análise Forense de Malware Brasileiro Direcionado ao Padrão Bancário CNAB240/400



**Data da análise:** 26 de Maio de 2026
**Família:** CNABHunter / Nuikita
**Origem:** Brasil
**Severidade:** **CRÍTICA
Confidencialidade:** Threat Intelligence Pública



## RESUMO EXECUTIVO

Durante operação de threat hunting focada em ameaças financeiras brasileiras, conduzimos análise forense completa de uma nova amostra do malware **CNABHunter (também conhecido como "Nuikita")**, recuperada do repositório MalwareBazaar (abuse.ch).

Diferente dos banking trojans tradicionais que miram credenciais via overlays bancários (Maverick, Coyote, Grandoreiro), o CNABHunter representa uma **mudança estratégica de paradigma**: ao invés de atacar o usuário final, o malware mira a **infraestrutura corporativa de processamento financeiro**, especificamente arquivos no padrão **CNAB240/CNAB400** — formato utilizado pelos bancos brasileiros para processamento em lote de boletos, cobranças, pagamentos e transferências.

### Implicações para o negócio

|Vetor de Risco|Impacto Potencial|
|-|-|
|**Manipulação de arquivos CNAB**|Desvio de pagamentos em lote|
|**Comprometimento de ERPs**|Acesso a fluxo financeiro corporativo|
|**Persistência em ambiente bancário**|Exfiltração contínua de dados de pagamento|
|**Compromisso da cadeia de pagamentos**|Fraude em larga escala (B2B)|





## 1\. CADEIA DE CUSTÓDIA

A análise foi conduzida seguindo metodologia forense rigorosa, com geração de hashes criptográficos imediatamente após recepção da amostra:

### Identificação da Amostra

```
Nome da amostra:    75f48cf77fe05e4e8e8b21e4ff3c3b611ddc7a8364a61e36eed428be939a97da.exe
Fonte:              MalwareBazaar (abuse.ch)
Família:            CNABHunter / Nuikita
Tipo:               PE32+ Windows x86-64 (Dropper)
Tamanho:            6.691.840 bytes (6,7 MB)
Compilação:         27/Abril/2026 13:36:21 UTC
Assinatura digital: AUSENTE
```

### Hashes Criptográficos

```
SHA-256: 75f48cf77fe05e4e8e8b21e4ff3c3b611ddc7a8364a61e36eed428be939a97da
SHA-1:   95e69a29bf8f2658d3d56f099cbe5a8cae3781c5
MD5:     2b19d93f39a82a3a583f652bbe8c395f
```

### Payload Interno

```
Nome:    cliente.dll
Tamanho: 13.985.792 bytes (13,3 MB)
SHA-256: 6a5db602b9f4e59a3393c4d0af9c4f80104e8c3d71ebc7c52faf1771456712b4
Função:  Módulo principal de espionagem (Python compilado via Nuitka)
```



## 2\. METODOLOGIA APLICADA

A análise seguiu framework forense estruturado em **6 etapas**, todas conduzidas em **análise estática controlada** (sem execução do binário):

### Etapa 1 — Triagem inicial

* Identificação de formato (PE32+ x64)
* Validação de integridade via hashing triplo (MD5/SHA-1/SHA-256)
* Verificação de assinatura digital
* Determinação de timestamp de compilação

### Etapa 2 — Análise de cabeçalho PE

* **Ferramentas:** `readpe`, `pesec`
* Mapeamento das 7 seções do binário
* Identificação de característica anômala: **97% do binário concentrado em `.rsrc`**
* Análise de entropia por seção (técnica para detecção de packers)

### Etapa 3 — Cálculo de entropia

* **Achado crítico:** Seção `.rsrc` apresentou entropia de **7.9991** (máximo teórico: 8.0)
* Indicador clássico de **payload criptografado ou comprimido**
* Sinal forte de mecanismo de evasão (packer/obfuscation)

### Etapa 4 — Extração de recursos embutidos

* Parser customizado em Python para o Resource Directory
* Identificação de magic bytes `4B 41 59 28 B5 2F FD` (KAY + ZSTD)
* Confirmação: framework **Nuitka onefile com compressão Zstandard**
* Origem do alias "Nuikita" (Nuitka + Nikita/personificação)

### Etapa 5 — Descompressão e extração do payload

* Descompressão via biblioteca `zstandard` em Python
* Parser do formato Nuitka onefile container
* **15 arquivos extraídos**, incluindo o módulo malicioso principal

### Etapa 6 — Análise estática do payload

* Extração de strings com `pestr`
* Identificação de C2 hardcoded
* Mapeamento de APIs Windows utilizadas
* Análise de exports e imports da DLL maliciosa



## 3\. ACHADOS CRÍTICOS

### 3.1. Anatomia do Dropper — Camada externa

A camada externa é um **loader sofisticado** que utiliza técnicas de evasão modernas:

```
┌─────────────────────────────────────────────────┐
│  DROPPER (6,7 MB)                               │
│  ┌────────────────────────────────────────────┐ │
│  │ .text (137 KB) - Loader Code               │ │
│  │   • FindResourceA / LoadResource           │ │
│  │   • VirtualProtect (modificação de perms)  │ │
│  │   • CreateProcessW (execução)              │ │
│  ├────────────────────────────────────────────┤ │
│  │ .rsrc (6,5 MB) - PAYLOAD CRIPTOGRAFADO     │ │
│  │   • Entropia: 7.9991                       │ │
│  │   • Magic: "KAY" + ZSTD                    │ │
│  │   • Framework: Nuitka onefile              │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

**Por que isso importa:** O uso de **Nuitka** (compilador Python → C → binário nativo) é incomum em malware brasileiro. Os trojans tradicionais (Maverick, Coyote, Grandoreiro) são escritos em Delphi ou .NET. A escolha do Nuitka indica:

1. **Maior dificuldade de detecção** por antivírus tradicionais
2. **Análise reversa mais complexa** (código nativo ofuscado)
3. **Desenvolvedor com perfil moderno** (Python + ferramentas atuais)

### 3.2. Anatomia do Payload — Camada interna

Após descompressão, o payload revela um ambiente Python completo:

```
PAYLOAD DESCOMPACTADO (27,3 MB)
├── cliente.dll (13,3 MB)  ← MÓDULO PRINCIPAL DE ESPIONAGEM
├── python313.dll (6,1 MB) ← Interpretador Python 3.13 embutido
├── libcrypto-3.dll (5,2 MB) ← OpenSSL para C2 criptografado
├── libssl-3.dll (794 KB)
├── \_ssl.pyd, \_socket.pyd
├── \_wmi.pyd ← Windows Management (reconhecimento)
├── \_hashlib.pyd, \_lzma.pyd, \_bz2.pyd
└── Módulos Python standard
```

### 3.3. Strings Reveladoras (Português)

A análise de strings do `cliente.dll` confirmou origem brasileira através de variáveis e funções em português:

```
arquivo\_estado
estado\_arquivos
arquivo\_zip\_interno
arquivos\_lidos\_nesta\_sessao
enviar\_para\_db\_flask
flask\_url
alterar\_arquivo
salvar\_estado
```

**Análise contextual:** Os nomes de funções demonstram comportamento **focado em manipulação de arquivos**, não em captura de credenciais. Isso é coerente com o modus operandi do CNABHunter — procurar, ler, **alterar** arquivos no formato CNAB no sistema da vítima.

### 3.4. Command \& Control (C2)

```
URL hardcoded: http://104.245.245.50:5000
Framework:     Flask (Python web server)
Protocolo:     HTTP (não-HTTPS)
```

**Sinais relevantes:**

* C2 sem TLS (vulnerável a MITM, mas funcional)
* Porta 5000 = padrão Flask (provavelmente servidor de desenvolvimento, baixa OPSEC do operador)
* IP estático (não usa fast-flux ou DGA)

A baixa sofisticação operacional do C2 contrasta com a sofisticação técnica do payload — sugere **operador brasileiro independente** ou grupo pequeno, não APT estatal.

### 3.5. APIs Windows Utilizadas

O conjunto de APIs importadas confirma capacidades de **dropper + RAT modular**:

|API|Propósito|TTP MITRE ATT\&CK|
|-|-|-|
|`FindResourceA` + `LoadResource`|Carregamento do payload embutido|T1027|
|`VirtualProtect`|Modificação de permissões de memória|T1055|
|`CreateProcessW`|Execução do payload extraído|T1106|
|`LoadLibraryExW` + `GetProcAddress`|Carregamento dinâmico (anti-análise)|T1574|
|`CreateFileW` + `WriteFile`|Manipulação de arquivos|T1005|
|Módulo `\_wmi.pyd` (Python)|Reconhecimento via WMI|T1047|
|Módulo `\_socket.pyd` (Python)|Comunicação de rede|T1071|



## 4\. POR QUE O CNAB240/400 É UM ALVO ESTRATÉGICO

Para executivos não familiarizados com o ecossistema bancário brasileiro:

### O que é CNAB240/CNAB400

CNAB (Centro Nacional de Automação Bancária) é o padrão de arquivo definido pela FEBRABAN para comunicação automatizada entre empresas e bancos. É utilizado para:

* **Remessa de boletos em lote** (cobrança)
* **Pagamento de fornecedores em massa**
* **Folhas de pagamento corporativas**
* **Transferências programadas (TED/DOC em lote)**
* **Conciliação bancária automatizada**

### Por que isso é crítico

Empresas brasileiras de médio e grande porte processam **milhares de transações diárias** via CNAB através de seus sistemas ERP (TOTVS Protheus, SAP, Senior, Sankhya, etc.). Os arquivos CNAB são gerados pelo ERP e enviados aos bancos via gateway financeiro.

**Vetor de ataque do CNABHunter:**

```
   ┌──────────┐     ┌───────────┐     ┌──────────┐
   │   ERP    │ ──→ │  Arquivo  │ ──→ │  Banco   │
   │  (TOTVS) │     │   CNAB    │     │ (Itaú/BB)│
   └──────────┘     └─────┬─────┘     └──────────┘
                          │
                          ↓ INTERCEPTAÇÃO
                    ┌───────────────┐
                    │  CNABHunter   │
                    │  modifica:    │
                    │  • Beneficiários│
                    │  • Valores    │
                    │  • Contas     │
                    └───────────────┘
```

### Impacto financeiro estimado

Um único arquivo CNAB pode conter **centenas de pagamentos** somando **dezenas de milhões de reais**. A modificação de campos específicos (conta destino, beneficiário) em pagamentos selecionados pode resultar em:

* **Desvio único de R$ 50k-500k** facilmente disfarçado em meio a pagamentos legítimos
* **Detecção tardia** (somente na conciliação bancária subsequente)
* **Recuperação muito difícil** (transferências bancárias B2B raramente são revertidas)



## 5\. INDICADORES DE COMPROMISSO (IOCs)

### Hashes para bloqueio em EDR/Antivírus

```
SHA-256 (Dropper):
75f48cf77fe05e4e8e8b21e4ff3c3b611ddc7a8364a61e36eed428be939a97da

SHA-256 (Payload cliente.dll):
6a5db602b9f4e59a3393c4d0af9c4f80104e8c3d71ebc7c52faf1771456712b4

MD5 (Dropper):
2b19d93f39a82a3a583f652bbe8c395f

SHA-1 (Dropper):
95e69a29bf8f2658d3d56f099cbe5a8cae3781c5
```

### Network Indicators

```
IP de C2:    104.245.245.50
Porta:       5000/tcp
Protocolo:   HTTP
Framework:   Flask
```

### File System Patterns

```
%TEMP%\\onefile\_{PID}\_{TIME}\\     ← Padrão Nuitka unpacking
cliente.dll                       ← Payload principal extraído
python313.dll                     ← Indicador de Python embutido em TEMP
```

### Behavioral Indicators

* Processo .exe não-assinado em `%TEMP%` carregando `python313.dll`
* Conexões HTTP para IP brasileiro não-categorizado em porta não-padrão
* Acesso/modificação de arquivos com extensões `.REM`, `.RET`, `.CNB` (formatos CNAB)
* Queries WMI a partir de processo Python em diretório temporário



## 6\. CONTEXTUALIZAÇÃO NO CENÁRIO BRASILEIRO

O CNABHunter se insere em um cenário de **escalada significativa de ameaças financeiras brasileiras** identificadas em 2026:

|Família|Vetor Principal|Alvo|
|-|-|-|
|**Coyote**|Browser overlays|Credenciais bancárias|
|**Maverick / TCLBANKER**|Worm via WhatsApp/Outlook|59 bancos/fintechs|
|**Grandoreiro**|E-mail phishing|Credenciais (LATAM)|
|**GoPix**|Pix manipulation|Transações instantâneas|
|**VENON** (Rust)|LNK hijacking|33 plataformas financeiras|
|**CNABHunter** |**ERP + CNAB files**|**Pagamentos corporativos B2B**|

**O diferencial do CNABHunter:** enquanto outras famílias miram **pessoa física** com overlays bancários ou phishing, o CNABHunter mira **pessoa jurídica** atacando a infraestrutura de processamento financeiro corporativo. O ROI por vítima é significativamente maior — uma única empresa comprometida pode gerar fraudes na casa dos **R$ milhões**, contra os R$ centenas-milhares típicos de fraude com pessoa física.



## 7\. CONCLUSÃO E POSICIONAMENTO

O CNABHunter representa uma evolução preocupante do cybercrime brasileiro: **menos ruído, mais precisão, maior payoff**. Ao invés de roubar credenciais de 10.000 vítimas para tentar transferências individuais, os operadores miram **uma única empresa** com **um único arquivo CNAB** contendo **centenas de pagamentos legítimos** — e desviam silenciosamente uma fração.

A análise aqui apresentada visa contribuir com a comunidade de threat intel nacional. 



## REFERÊNCIAS

* MalwareBazaar (abuse.ch): repositório de origem da amostra
* Pesquisa independente sobre CNABHunter: @johnk3r (Twitter/X)
* MITRE ATT\&CK Framework
* FEBRABAN — Documentação CNAB240/CNAB400
* Elastic Security Labs — TCLBANKER (família correlata)



## SOBRE ESTA ANÁLISE

Esta análise foi conduzida em ambiente forense controlado, com finalidade exclusiva de pesquisa defensiva. Nenhum binário foi executado em ambiente de produção. Todos os IOCs são compartilhados em conformidade com práticas de TLP:WHITE.





