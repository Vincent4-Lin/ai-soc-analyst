# AI SOC Analyst 專案說明

這是一個本機端資安分析工具，用來輔助 SOC / 資安初學者快速 triage log、掃描報告和可疑 email。專案重點不是直接取代資安分析師，而是把常見的第一輪檢查自動化，再用 LLM 把證據整理成可讀的分析報告。

## 專案目標

這個工具主要做三件事：

1. 先用 Python 本地規則抽出可疑指標。
2. 再把本地分析結果交給 Groq LLM 做內容理解和報告整理。
3. 在前端顯示風險分數、findings、IOCs、timeline 和 Markdown 報告。

整體流程：

```text
使用者貼上 log / email
↓
Python 本地分析
↓
抽出 IP、URL、domain、port、CVE、hash、可疑行為
↓
如果有啟用 LLM，送 redacted 內容和本地證據給 Groq
↓
產生中文資安分析報告
```

## 功能模式

### 1. Log Analyzer

Log 模式可以分析 SSH、Nginx、EDR、Nmap、Trivy、OpenVAS、Windows Event 等文字內容。

目前會偵測：

- SSH brute force
- 成功登入事件
- Web exploit probe
- 可疑 command execution
- sudo / privilege escalation
- malware / EDR alert
- exfiltration hint
- critical vulnerability scanner finding

也會抽出：

- IPv4
- URL
- domain
- email
- CVE
- MD5 / SHA1 / SHA256 hash

### 2. Email Analyzer

Email 模式用來分析 phishing email。可以貼上完整 `.eml` 原文，包含 headers 和 body。

Email 模式採用兩階段流程：

```text
第一階段：IP / Port / URL Precheck
↓
先判斷網路指標是否可疑
↓
第二階段：LLM Email 內容分析
↓
判斷內容是否像 phishing、詐騙、正常通知或證據不足
```

第一階段會檢查：

- URL 是否使用 IP 而不是 domain
- URL 是否使用非標準 port，例如 `8080`
- 是否使用 HTTP 要求登入或驗證帳號
- 顯示連結文字和實際 href 是否不同
- 是否有 URL shortener
- 是否有 punycode domain
- IP 是 public / private / reserved / loopback

第二階段會用 LLM 分析：

- 信件是否像 phishing
- 是否有緊急、威脅、催促語氣
- 是否要求密碼、OTP、付款、登入或驗證
- 寄件者身份是否合理
- 對一般使用者和 SOC 的建議處置

Email 模式也會檢查 header：

- SPF
- DKIM
- DMARC
- From / Reply-To mismatch
- From / Return-Path mismatch

## LLM 在這個專案中做什麼

LLM 不是第一層偵測器。第一層判斷由 Python 本地規則完成。

LLM 主要負責：

- 閱讀本地分析證據
- 理解 email / log 的上下文
- 判斷 phishing 或 incident 的可能性
- 產生繁體中文報告
- 給出 SOC 後續調查建議
- 把技術證據轉成一般使用者也看得懂的說明

本地程式主要負責：

- 抽 IOCs
- 判斷 IP / port / URL 是否有明顯可疑點
- 偵測常見 log pattern
- redaction secrets
- risk score

## 使用的 API

目前使用 Groq 的 OpenAI-compatible LLM API：

```text
https://api.groq.com/openai/v1
```

預設模型：

```text
llama-3.3-70b-versatile
```

API key 透過 `.env` 設定：

```text
GROQ_API_KEY=your_key_here
```

注意：不要把 `.env` 推到 GitHub。專案已經用 `.gitignore` 排除 `.env`。

## 如何執行

進入專案資料夾：

```bash
cd /Users/hayashimeisaki/Documents/Codex/2026-06-05/gsk-yiiqryklornjxvhslyntwgdyb3fyeru18phyduczxqfbbtg8uf9h-llm-api-project
```

如果還沒有 `.env`，建立一次：

```bash
cp .env.example .env
```

之後編輯 `.env`：

```bash
nano .env
```

測試 LLM API：

```bash
python3 scripts/check_llm_api.py
```

啟動本機 Web app：

```bash
python3 app.py
```

瀏覽器開：

```text
http://127.0.0.1:8787
```

## 專案結構

```text
app.py                     本機 Web server 和 API endpoint
soc_analyzer.py            Log / scanner report 分析邏輯
phishing_analyzer.py       Email phishing 分析邏輯
scripts/check_llm_api.py   Groq API 測試腳本
static/index.html          前端頁面
static/styles.css          前端樣式
static/app.js              前端互動和 API 呼叫
samples/                   範例 log 和 email
tests/                     單元測試
```

## 測試

跑全部測試：

```bash
python3 -m unittest discover -s tests
```

目前測試涵蓋：

- SSH brute force detection
- secret redaction
- phishing email indicators
- IP / port / URL precheck suspicious path
- IP / port / URL precheck clean path

## 目前限制

這個專案目前是 MVP，還不是完整 SOC 平台。

目前沒有做：

- 真正查 threat intelligence reputation
- DNS lookup
- WHOIS lookup
- VirusTotal 查詢
- URL sandbox detonation
- port scan
- SIEM 整合
- EDR 整合
- 使用者登入和權限管理

所以它現在判斷的是：

```text
根據 email/log 內容本身，是否有可疑跡象
```

不是：

```text
這個 IP/domain 一定是惡意
```

## 未來可以加的功能

可以繼續擴充：

- VirusTotal API 查 hash / domain / URL
- AbuseIPDB 查 IP reputation
- URLScan.io 查 URL
- SPF / DKIM / DMARC 更完整 parser
- 匯出 PDF 報告
- 儲存歷史分析結果
- 支援拖曳上傳 `.eml`
- 支援 MISP / OpenCTI threat intel
- 支援 SIEM query 建議，例如 Splunk / Elastic / Sentinel

## 安全注意事項

- 不要把 `.env` 推到 GitHub。
- 如果 API key 貼到聊天、GitHub 或截圖裡，要立刻 revoke / rotate。
- LLM 前會做基本 secret redaction，但仍不要上傳真實敏感資料。
- 這個工具只應用於自己有授權分析的 log、email 和掃描結果。
