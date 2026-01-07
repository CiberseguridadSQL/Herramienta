"""
Módulo de Generación de Reportes
Genera reportes en formato HTML con diseño profesional y evidencia inteligente.
"""

import json
import os
from typing import Dict, List, Optional
from datetime import datetime
from html import escape

class ReportGenerator:
    """Generador de reportes con soporte para Smart Preview y Snippets de Error."""

    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_console_report(self, results: Dict, verbose: bool = True) -> str:
        """
        Genera el reporte de texto para la consola. 
        Esta función es necesaria para que detector.py no lance error.
        """
        output = []
        output.append("\n" + "="*80)
        output.append("SQL INJECTION SCANNER - CONSOLE SUMMARY")
        output.append("="*80)
        output.append(f"Generated: {self.timestamp}\n")
        
        total_vulns = 0
        for endpoint, data in results.items():
            scan_results = data.get('results', [])
            vulns = [r for r in scan_results if r.get('detector_result', {}).get('vulnerable', False)]
            if vulns:
                total_vulns += len(vulns)
                output.append(f"[!] {data.get('url')} - Vulnerabilidades: {len(vulns)}")
        
        output.append(f"\nTotal Vulnerabilidades detectadas: {total_vulns}")
        output.append("="*80 + "\n")
        return "\n".join(output)

    def generate_html_report(self, results: Dict, filepath: str):
        """Genera reporte HTML manteniendo el estilo visual original."""
        html_content = self._generate_html_content(results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to {filepath}")

    def _generate_html_content(self, results: Dict) -> str:
        """Genera el contenido HTML con indentación clara y CSS original."""
        
        # Estadísticas globales
        total_endpoints = len(results)
        total_vulnerabilities = 0
        vulnerable_endpoints = 0
        
        for endpoint_data in results.values():
            scan_results = endpoint_data.get('results', [])
            vulns = [r for r in scan_results if r.get('detector_result', {}).get('vulnerable', False)]
            if vulns:
                vulnerable_endpoints += 1
                total_vulnerabilities += len(vulns)

        # Inicio del documento HTML
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Scanner - Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        h2 {{
            color: #1976d2;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-left: 10px;
            border-left: 4px solid #1976d2;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-card h3 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .vulnerability {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        .vulnerability.high {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        .payload {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            word-break: break-all;
        }}
        .evidence {{
            background: #e9ecef;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 5px 5px 5px 0;
        }}
        .badge.high {{
            background: #dc3545;
            color: white;
        }}
        .badge.type {{
            background: #6c757d;
            color: white;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        table th, table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        table th {{
            background: #343a40;
            color: white;
        }}
        .snippet-box {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin-top: 10px;
            border-left: 4px solid #d32f2f;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SQL Injection Scanner - Security Report</h1>
        <p>Generated: {self.timestamp}</p>
        
        <div class="summary">
            <div class="summary-card">
                <h3>{total_endpoints}</h3>
                <p>Endpoints Scanned</p>
            </div>
            <div class="summary-card">
                <h3>{vulnerable_endpoints}</h3>
                <p>Vulnerable Endpoints</p>
            </div>
            <div class="summary-card">
                <h3>{total_vulnerabilities}</h3>
                <p>Total Vulnerabilities</p>
            </div>
        </div>
"""

        for endpoint, endpoint_data in results.items():
            scan_results = endpoint_data.get('results', [])
            vulnerabilities = [r for r in scan_results if r.get('detector_result', {}).get('vulnerable', False)]
            
            if vulnerabilities:
                html += f"<h2>📍 {escape(endpoint)}</h2>"
                
                for res in vulnerabilities:
                    det = res.get('detector_result', {})
                    indicators = det.get('indicators', {})
                    conf = det.get('confidence', 'low')
                    
                    html += f"""
        <div class="vulnerability {conf}">
            <h3>[!] VULNERABLE - Parameter: <code>{escape(res.get('param', ''))}</code></h3>
            <div class="payload">
                <strong>Payload:</strong> {escape(det.get('payload', ''))}
            </div>
            
            <span class="badge type">{escape(det.get('vulnerability_type', ''))}</span>
            <span class="badge {conf}">Confidence: {conf.upper()}</span>
            
            <div class="evidence">
                <strong>Evidence:</strong>
                <ul style="margin-left: 20px; margin-top: 5px;">
                    {"".join([f"<li>{escape(str(ev))}</li>" for ev in det.get('evidence', [])])}
                </ul>
            </div>
"""
                    # Lógica de Evidencia Inteligente
                    if 'error_snippet' in indicators:
                        html += f"""
            <div class="snippet-box">
                <strong>🔎 SQL Error Found:</strong>
                <pre style="margin-top: 5px; white-space: pre-wrap;">{escape(indicators['error_snippet'])}</pre>
            </div>
"""
                    # Mostrar query filtrada si existe
                    if 'filtered_query' in indicators:
                        html += f"""
            <div class="snippet-box" style="border-left-color: #ffc107;">
                <strong>⚠️ Leaked Query:</strong>
                <pre style="margin-top: 5px; white-space: pre-wrap; color: #f1c40f;">{escape(indicators['filtered_query'])}</pre>
            </div>
"""
                        # Además, si existe un preview inteligente distinto, mostrar también
                        if 'response_preview' in indicators and indicators['response_preview'] != indicators.get('filtered_query'):
                            html += f"""
            <div class="snippet-box" style="background: #f8f9fa; color: #333; border-left-color: #6c757d;">
                <strong>📄 Smart Preview:</strong>
                <pre style="margin-top: 5px; white-space: pre-wrap; color: #555; font-size: 0.9em;">{escape(indicators['response_preview'])}</pre>
            </div>
"""
                    # Si no hay query filtrada pero sí preview, mostrar solo el preview
                    elif 'response_preview' in indicators:
                        html += f"""
            <div class="snippet-box" style="background: #f8f9fa; color: #333; border-left-color: #6c757d;">
                <strong>📄 Response Preview (Smart Context):</strong>
                <pre style="margin-top: 5px; white-space: pre-wrap; color: #555; font-size: 0.9em;">{escape(indicators['response_preview'])}</pre>
            </div>
"""

                    # Tabla de métricas
                    resp_len = len(res.get('text', ''))
                    base_len = det.get('base_length', 0)
                    
                    html += f"""
            <table>
                <thead>
                    <tr><th>Metric</th><th>Value</th></tr>
                </thead>
                <tbody>
                    <tr><td>Status Code</td><td>{res.get('status_code')}</td></tr>
                    <tr><td>Response Length</td><td>{resp_len} bytes</td></tr>
                    <tr><td>Base Length</td><td>{base_len} bytes</td></tr>
                    <tr><td>Length Difference</td><td>{abs(resp_len - base_len)} bytes</td></tr>
                </tbody>
            </table>
        </div>
"""

        html += """<div class="footer" style="text-align: center; margin-top: 40px; color: #6c757d;"><p>Generated by SQL Injection Scanner</p></div></div></body></html>"""
        return html