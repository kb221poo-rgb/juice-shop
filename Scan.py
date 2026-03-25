import argparse
import time
import os
import platform
import subprocess
from fpdf import FPDF

def print_banner():
    print("=" * 60)
    print("    HYBRID SAST+DAST SECURITY AGGREGATOR v4.0 (UA Edition)")
    print("    Розроблено для дипломного проєкту")
    print("=" * 60)

def load_sast_data():
    print("[+] Завантаження результатів SAST (GitHub CodeQL)...")
    time.sleep(1)
    return [
        {
            "name": "SQL Injection", "severity": "High", "source": "SAST",
            "desc": "Неправильна нейтралізація спеціальних символів у SQL-командах (SQL-ін'єкція).",
            "sol": "Використовуйте параметризовані запити або підготовлені вирази (prepared statements) замість склеювання рядків."
        },
        {
            "name": "Cross-Site Scripting (XSS)", "severity": "Medium", "source": "SAST",
            "desc": "Додаток виводить ненадійні дані користувача на веб-сторінку без належної перевірки або екранування.",
            "sol": "Застосовуйте контекстно-залежне екранування до всього вводу користувача перед його відображенням у браузері."
        },
        {
            "name": "Server-Side Request Forgery", "severity": "High", "source": "SAST",
            "desc": "Веб-додаток завантажує віддалений ресурс без перевірки URL-адреси, яку надав користувач.",
            "sol": "Реалізуйте суворий 'білий список' (allowlist) дозволених доменів та IP-адрес для вихідних запитів."
        },
        {
            "name": "Dangerous JS Functions", "severity": "Low", "source": "SAST",
            "desc": "Використання потенційно небезпечних JavaScript-функцій, таких як eval() або innerHTML.",
            "sol": "Уникайте використання eval(). Використовуйте безпечний textContent замість innerHTML там, де це можливо."
        }
    ]

def load_dast_data():
    print("[+] Завантаження результатів DAST (OWASP ZAP)...")
    time.sleep(1)
    return [
        {
            "name": "SQL Injection", "severity": "High", "source": "DAST",
            "desc": "Неправильна нейтралізація спеціальних символів у SQL-командах (SQL-ін'єкція).",
            "sol": "Використовуйте параметризовані запити або підготовлені вирази (prepared statements) замість склеювання рядків."
        },
        {
            "name": "Content Security Policy Missing", "severity": "Medium", "source": "DAST",
            "desc": "Заголовок безпеки Content Security Policy (CSP) не встановлено, що залишає сайт вразливим до XSS-атак.",
            "sol": "Переконайтеся, що ваш веб-сервер налаштовано на передачу суворого HTTP-заголовка Content-Security-Policy."
        },
        {
            "name": "Cross-Domain Misconfig", "severity": "Medium", "source": "DAST",
            "desc": "CORS налаштовано небезпечно (Access-Control-Allow-Origin: *), що дозволяє стороннім сайтам читати дані.",
            "sol": "Налаштуйте HTTP-заголовок Access-Control-Allow-Origin на більш обмежений набір довірених доменів."
        },
        {
            "name": "Timestamp Disclosure", "severity": "Low", "source": "DAST",
            "desc": "Додаток або веб-сервер розкриває системні часові мітки (Unix Timestamp).",
            "sol": "Вручну переконайтеся, що дані часових міток не є конфіденційними і не можуть бути використані зловмисником."
        }
    ]

def aggregate_results(sast_findings, dast_findings):
    print("[+] Аналіз вразливостей та агрегація (пошук дублікатів)...")
    time.sleep(1.5)
    aggregated_report = {}
    
    for finding in sast_findings:
        vuln_name = finding["name"]
        aggregated_report[vuln_name] = {
            "severity": finding["severity"], 
            "detected_by": [finding["source"]],
            "desc": finding["desc"],
            "sol": finding["sol"]
        }
        
    for finding in dast_findings:
        vuln_name = finding["name"]
        if vuln_name in aggregated_report:
            if finding["source"] not in aggregated_report[vuln_name]["detected_by"]:
                aggregated_report[vuln_name]["detected_by"].append(finding["source"])
        else:
            aggregated_report[vuln_name] = {
                "severity": finding["severity"], 
                "detected_by": [finding["source"]],
                "desc": finding["desc"],
                "sol": finding["sol"]
            }
            
    return aggregated_report

class PDF(FPDF):
    def header(self):
        # Налаштовуємо шрифт
        self.set_font('ArialU', 'B', 15)
        self.cell(0, 10, 'ГІБРИДНИЙ ЗВІТ БЕЗПЕКИ (SAST + DAST)', 0, 1, 'C')
        self.set_font('ArialU', '', 10)
        self.cell(0, 10, 'Згенеровано модулем DevSecOps Aggregator', 0, 1, 'C')
        self.ln(5)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('ArialU', '', 8)
        self.cell(0, 10, f'Сторінка {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(report, filename="Security_Report_UA.pdf"):
    print("[+] Генерація офіційного PDF-звіту українською мовою...")
    time.sleep(1)
    
    pdf = PDF()
    
    # ПІДКЛЮЧЕННЯ ШРИФТІВ WINDOWS ДЛЯ КИРИЛИЦІ
    font_path_regular = r'C:\Windows\Fonts\arial.ttf'
    font_path_bold = r'C:\Windows\Fonts\arialbd.ttf'
    
    try:
        pdf.add_font('ArialU', '', font_path_regular, uni=True)
        pdf.add_font('ArialU', 'B', font_path_bold, uni=True)
    except Exception as e:
        print(f"[!] Увага: Не вдалося завантажити український шрифт ({e}). Текст може відображатися некоректно.")
    
    # СТОРІНКА 1: Зведена таблиця
    pdf.add_page()
    pdf.set_font("ArialU", 'B', 14)
    pdf.cell(0, 10, '1. Загальний огляд вразливостей (Executive Summary)', 0, 1, 'L')
    pdf.ln(2)
    
    pdf.set_font("ArialU", 'B', 11)
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(90, 10, 'Назва загрози', 1, 0, 'C', 1)
    pdf.cell(30, 10, 'Рівень', 1, 0, 'C', 1)
    pdf.cell(60, 10, 'Знайдено сканером', 1, 1, 'C', 1)
    
    severity_order = {"High": 1, "Medium": 2, "Low": 3}
    sorted_report = sorted(report.items(), key=lambda x: severity_order.get(x[1]["severity"], 4))
    
    pdf.set_font("ArialU", '', 11)
    for name, data in sorted_report:
        sources = " + ".join(data["detected_by"])
        pdf.cell(90, 10, name, 1)
        pdf.cell(30, 10, data['severity'], 1, 0, 'C')
        pdf.cell(60, 10, sources, 1, 1, 'C')
        
    pdf.ln(5)
    pdf.set_font("ArialU", 'B', 11)
    pdf.cell(0, 10, f'Всього унікальних загроз виявлено: {len(report)}', 0, 1)
    
    # СТОРІНКА 2: Детальний опис
    pdf.add_page()
    pdf.set_font("ArialU", 'B', 14)
    pdf.cell(0, 10, '2. Детальний аналіз та шляхи вирішення (Remediation)', 0, 1, 'L')
    pdf.ln(5)
    
    for name, data in sorted_report:
        # Назва
        pdf.set_font("ArialU", 'B', 12)
        pdf.set_text_color(180, 0, 0) if data['severity'] == 'High' else pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, f"[ {data['severity'].upper()} ] {name}", 0, 1, 'L')
        pdf.set_text_color(0, 0, 0)
        
        # Опис
        pdf.set_font("ArialU", 'B', 10)
        pdf.cell(0, 6, "Опис проблеми:", 0, 1, 'L')
        pdf.set_font("ArialU", '', 10)
        pdf.multi_cell(0, 5, data['desc'])
        
        # Рішення
        pdf.set_font("ArialU", 'B', 10)
        pdf.cell(0, 6, "Рекомендації щодо усунення:", 0, 1, 'L')
        pdf.set_font("ArialU", '', 10)
        pdf.multi_cell(0, 5, data['sol'])
        
        pdf.ln(6)
    
    pdf.output(filename)
    print(f"[v] Звіт успішно збережено як {filename}")
    return filename

def open_file(filepath):
    print("[+] Відкриття PDF-документа...")
    if platform.system() == 'Darwin':
        subprocess.call(('open', filepath))
    elif platform.system() == 'Windows':
        os.startfile(filepath)
    else:
        subprocess.call(('xdg-open', filepath))

def main():
    parser = argparse.ArgumentParser(description="Агрегатор звітів SAST та DAST")
    parser.add_argument('--demo', action='store_true', help="Запустити в демо-режимі")
    args = parser.parse_args()

    print_banner()
    if args.demo:
        sast = load_sast_data()
        dast = load_dast_data()
        final_report = aggregate_results(sast, dast)
        
        pdf_file = generate_pdf_report(final_report)
        open_file(pdf_file)
    else:
        print("[!] Помилка: Вкажіть прапорець --demo")

if __name__ == "__main__":
    main()
