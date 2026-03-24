import argparse
import time

def print_banner():
    print("=" * 60)
    print("    HYBRID SAST+DAST SECURITY AGGREGATOR v1.0")
    print("=" * 60)

def load_sast_data():
    # Імітація парсингу JSON-звіту від GitHub CodeQL
    print("[+] Завантаження результатів SAST (GitHub CodeQL)...")
    time.sleep(1)
    return [
        {"name": "SQL Injection", "severity": "High", "source": "SAST"},
        {"name": "Cross-Site Scripting (XSS)", "severity": "Medium", "source": "SAST"},
        {"name": "Server-Side Request Forgery (SSRF)", "severity": "High", "source": "SAST"},
        {"name": "Dangerous JS Functions", "severity": "Low", "source": "SAST"}
    ]

def load_dast_data():
    # Імітація парсингу HTML/JSON-звіту від OWASP ZAP
    print("[+] Завантаження результатів DAST (OWASP ZAP)...")
    time.sleep(1)
    return [
        {"name": "SQL Injection", "severity": "High", "source": "DAST"},
        {"name": "Content Security Policy (CSP) Missing", "severity": "Medium", "source": "DAST"},
        {"name": "Cross-Domain Misconfiguration", "severity": "Medium", "source": "DAST"},
        {"name": "Timestamp Disclosure - Unix", "severity": "Low", "source": "DAST"}
    ]

def aggregate_results(sast_findings, dast_findings):
    print("[+] Аналіз вразливостей та пошук перетинів (Агрегація)...")
    time.sleep(1.5)
    
    aggregated_report = {}
    
    # Додаємо SAST результати
    for finding in sast_findings:
        vuln_name = finding["name"]
        aggregated_report[vuln_name] = {
            "severity": finding["severity"],
            "detected_by": [finding["source"]]
        }
        
    # Додаємо DAST результати та шукаємо збіги
    for finding in dast_findings:
        vuln_name = finding["name"]
        if vuln_name in aggregated_report:
            # Якщо вразливість вже знайшов SAST, просто додаємо DAST як друге джерело
            aggregated_report[vuln_name]["detected_by"].append(finding["source"])
        else:
            # Якщо це нова вразливість, додаємо її в базу
            aggregated_report[vuln_name] = {
                "severity": finding["severity"],
                "detected_by": [finding["source"]]
            }
            
    return aggregated_report

def display_report(report):
    print("\n" + "=" * 60)
    print("                 ЗВЕДЕНИЙ ЗВІТ БЕЗПЕКИ")
    print("=" * 60)
    print(f"{'Вразливість':<40} | {'Рівень':<8} | {'Джерело'}")
    print("-" * 60)
    
    # Сортування: спочатку High, потім Medium, потім Low
    severity_order = {"High": 1, "Medium": 2, "Low": 3}
    sorted_report = sorted(report.items(), key=lambda x: severity_order.get(x[1]["severity"], 4))
    
    for name, data in sorted_report:
        sources = " + ".join(data["detected_by"])
        print(f"{name:<40} | {data['severity']:<8} | {sources}")
        
    print("-" * 60)
    print(f"Всього унікальних загроз виявлено: {len(report)}")
    print("=" * 60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Агрегатор звітів SAST та DAST")
    parser.add_argument('--demo', action='store_true', help="Запустити в демо-режимі на основі реальних даних")
    args = parser.parse_args()

    print_banner()
    
    if args.demo:
        sast = load_sast_data()
        dast = load_dast_data()
        final_report = aggregate_results(sast, dast)
        display_report(final_report)
    else:
        print("[!] Помилка: Вкажіть файли звітів або запустіть з прапорцем --demo")
        print("Приклад: python aggregator.py --demo")

if __name__ == "__main__":
    main()