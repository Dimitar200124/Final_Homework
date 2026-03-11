from artifact_collector import collect_artifacts
import os
import httpx
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import time

# добавляем API ключи VirusTotal и Vulners.com из переменных окружения
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise ValueError("API ключ не найден! Задайте переменную окружения VT_API_KEY.")

API_KEY2 = os.getenv("Vuln_API_KEY")
if not API_KEY2:
    raise ValueError("API ключ не найден! Задайте переменную окружения Vuln_API_KEY.")

events = []

# функция чтения eve.json
def read_eve_json(filepath: str) -> list:
    with open(filepath,'r', encoding='utf-8') as f:
        for line_number, line in enumerate(f, start=1):
             line = line.strip()
             if not line:
                 continue
             try:
                 event = json.loads(line)
                 events.append(event)
             except json.JSONDecodeError as e:
                 print(f"Ошибка JSON на строке {line_number}: {e}")
        return events       

HEADERS = {"x-apikey": API_KEY}
BASE = "https://www.virustotal.com/api/v3"

# проверки VirusTotal
def check_ip(ip: str):
    return httpx.get(f"{BASE}/ip_addresses/{ip}", headers = HEADERS).json()

def check_domain(domain: str):
    return httpx.get(f"{BASE}/domains/{domain}", headers = HEADERS).json()

def check_url(url: str):

    r = httpx.post(
        f"{BASE}/urls",
        headers=HEADERS,
        data={"url": url}
    )

    analysis_id = r.json()["data"]["id"]

    r2 = httpx.get(
        f"{BASE}/analyses/{analysis_id}",
        headers=HEADERS
    )

    return r2.json()

# проверка сигнатур через Vulners
def check_signature_vulners(signature):

    r = httpx.post(
        "https://vulners.com/api/v3/search/lucene/",
        headers={
            "X-Api-Key": API_KEY2,
            "Content-Type": "application/json"
        },
        json={
            "query": signature,
            "size": 3
        }
    )

    return r.json()


if __name__ == "__main__":

    LOG_FILE = input("Введите имя вашего лог-файла: ")

    print(f"Чтение лога: {LOG_FILE}")
    events = read_eve_json(LOG_FILE)

    print(f"Прочитано событий: {len(events)}")

    if not events:
        print("Нет валидных событий для анализа.")
        exit()

    print("Сбор артефактов...")
    artifacts = collect_artifacts(events)

    print("\nРезультат:")
    print(f"Всего уникальных IP:     {len(artifacts['all_ips'])}")
    print(f"Всего доменов:           {len(artifacts['domains'])}")
    print(f"Всего URL:               {len(artifacts['urls'])}")
    print(f"Уникальных сигнатур:     {len(artifacts['signatures'])}")

    print("\nСписок всех IP-адресов:")
    for ip in sorted(artifacts['all_ips']):
        print(f"  {ip}")

    # полный отчет
    report = {
        "ips": [],
        "domains": [],
        "urls": [],
        "signatures": []
    }

    # короткий отчет для статистики
    stats_report = {
        "ips": [],
        "domains": []
    }


# ===== IP =====

for ip in artifacts['all_ips']:

    result = check_ip(ip)

    print(f"\nРезультат проверки IP {ip}:")

    if 'data' in result:

        attributes = result['data']['attributes']
        stats = attributes['last_analysis_stats']

        print(f" Кол-во вредоносных: {stats['malicious']}")
        print(f" Кол-во подозрительных: {stats['suspicious']}")
        print(f" Кол-во безопасных: {stats['harmless']}")
        print(f" Кол-во неопределенных: {stats['undetected']}")

        report["ips"].append({
            "ip": ip,
            "stats": stats,
            "full_response": result
        })

        stats_report["ips"].append({
            "artifact": ip,
            "malicious": stats['malicious'],
            "suspicious": stats['suspicious'],
            "harmless": stats['harmless'],
            "undetected": stats['undetected']
        })

    else:
        print("Нет данных для этого IP")

    time.sleep(20)


# ===== DOMAINS =====

for domain in artifacts['domains']:

    result = check_domain(domain)

    print(f"\nРезультат проверки домена {domain}:")

    if "data" in result:

        attributes = result['data']['attributes']
        stats = attributes['last_analysis_stats']

        print(f" Кол-во детектов: {stats['malicious']}")
        print(f" Кол-во подозрительных: {stats['suspicious']}")
        print(f" Кол-во безопасных: {stats['harmless']}")
        print(f" Кол-во неопределенных: {stats['undetected']}")

        report["domains"].append({
            "domain": domain,
            "stats": stats,
            "full_response": result
        })

        stats_report["domains"].append({
            "artifact": domain,
            "malicious": stats['malicious'],
            "suspicious": stats['suspicious'],
            "harmless": stats['harmless'],
            "undetected": stats['undetected']
        })

    else:
        print("Нет данных для этого домена")

    time.sleep(20)


# ===== URL =====

for url in artifacts['urls']:

    result = check_url(url)

    print(f"\nРезультат проверки URL {url}:")

    if "data" not in result:
        print("Нет данных для этого URL")
        continue

    attributes = result["data"].get("attributes", {})
    stats = attributes.get("last_analysis_stats") or attributes.get("stats")

    if not stats:
        print("Нет статистики анализа")
        continue

    print(f" Кол-во детектов: {stats['malicious']}")
    print(f" Кол-во подозрительных: {stats['suspicious']}")
    print(f" Кол-во безопасных: {stats['harmless']}")
    print(f" Кол-во неопределенных: {stats['undetected']}")

    report["urls"].append({
        "url": url,
        "stats": stats,
        "full_response": result
    })

    time.sleep(20)


# ===== SIGNATURES =====

for signature in artifacts['signatures']:

    result = check_signature_vulners(signature)

    print(f"\nРезультат проверки сигнатуры: {signature}")

    if result.get("result") != "OK":
        print("Ошибка API")
        continue

    search_results = result.get("data", {}).get("search", [])

    if not search_results:
        print("Ничего не найдено")
        continue

    vulners_list = []

    for item in search_results:

        source = item.get("_source", {})

        title = source.get("title")
        type = source.get("type")
        cves = source.get("cvelist")
        cvss = source.get("cvss", {}).get("score")
        link = source.get("href")

        print(f" Title: {title}")
        print(f" Type: {type}")
        print(f" CVE: {cves}")
        print(f" CVSS: {cvss}")
        print(f" Link: {link}")

        vulners_list.append({
            "title": title,
            "type": type,
            "cves": cves,
            "cvss": cvss,
            "link": link
        })

    report["signatures"].append({
        "signature": signature,
        "results": vulners_list,
        "full_response": result
    })

    time.sleep(10)


# ===== Сохранение отчетов =====

with open("full_report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4, ensure_ascii=False)

print("\n[+] Полный отчет сохранён в full_report.json")

with open("stats_report.json", "w", encoding="utf-8") as f:
    json.dump(stats_report, f, indent=4, ensure_ascii=False)

print("[+] Короткий статистический отчет сохранён в stats_report.json")

#======= Делаем график по IP-адресам ==============================

with open("stats_report.json") as f: # читаем статистический отчет
    data = json.load(f)

df_ips = pd.DataFrame(data["ips"])

# переводим таблицу в "длинный формат"
df_long = df_ips.melt(
    id_vars="artifact",
    value_vars=["malicious", "suspicious", "harmless", "undetected"],
    var_name="verdict",
    value_name="count"
)

plt.figure(figsize=(12,6))

sns.barplot(
    data=df_long,
    x="artifact",
    y="count",
    hue="verdict"
)

plt.title("VirusTotal verdict для IP")
plt.xlabel("IP address")
plt.ylabel("Detections")

plt.xticks(rotation=45)

plt.legend(title="Verdict")

plt.tight_layout()
plt.show()

#======= Делаем график по доменам =========

df_domains = pd.DataFrame(data["domains"])

df_long = df_domains.melt(
    id_vars="artifact",
    value_vars=["malicious", "suspicious", "harmless", "undetected"],
    var_name="verdict",
    value_name="count"
)

plt.figure(figsize=(12,6))

sns.barplot(
    data=df_long,
    x="artifact",
    y="count",
    hue="verdict"
)

plt.title("VirusTotal verdict для доменов")
plt.xlabel("Domain")
plt.ylabel("Detections")

plt.xticks(rotation=45)

plt.tight_layout()
plt.show()