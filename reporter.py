"""
Módulo de Generación de Reportes
Genera reportes en formato HTML, JSON y consola
"""

import json
import os
from typing import Dict, List, Optional
from datetime import datetime
from html import escape

class ReportGenerator:
    """Generador de reportes profesionales"""
    
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_console_report(self, results: Dict, verbose: bool = True) -> str:
        """
        Genera reporte para consola
        """
        output = []
        output.append("\n" + "="*80)
        output.append("SQL INJECTION SCANNER - REPORT")
        output.append("="*80)
        output.append(f"Generated: {self.timestamp}\n")
        
        total_vulnerabilities = 0
        total_endpoints = len(results)
        
        for endpoint, endpoint_data in results.items():
            url = endpoint_data.get('url', endpoint)
            scan_results = endpoint_data.get('results', [])
            
            # Contar vulnerabilidades
            vuln_count = sum(1 for r in scan_results 
                           if r.get('detector_result', {}).get('vulnerable', False))
            
            if vuln_count > 0:
                total_vulnerabilities += vuln_count
                output.append(f"\n[!] ENDPOINT: {url}")
                output.append(f"    Vulnerabilities found: {vuln_count}")
                output.append("-" * 80)
                
                for result in scan_results:
                    detector_result = result.get('detector_result', {})
                    if detector_result.get('vulnerable', False):
                        payload = detector_result.get('payload', 'N/A')
                        vuln_type = detector_result.get('vulnerability_type', 'unknown')
                        confidence = detector_result.get('confidence', 'low')
                        param = result.get('param', 'N/A')
                        
                        output.append(f"\n  Parameter: {param}")
                        output.append(f"  Payload: {payload}")
                        output.append(f"  Type: {vuln_type}")
                        output.append(f"  Confidence: {confidence.upper()}")
                        
                        evidence = detector_result.get('evidence', [])
                        if evidence:
                            output.append("  Evidence:")
                            for ev in evidence[:3]:  # Mostrar solo 3 evidencias
                                output.append(f"    - {ev}")
                        
                        ml_result = result.get('ml_result', {})
                        if ml_result and ml_result.get('prediction') != 'unknown':
                            ml_prob = ml_result.get('probability', 0.0)
                            output.append(f"  ML Prediction: {ml_result.get('prediction')} ({ml_prob:.1%})")
        
        output.append("\n" + "="*80)
        output.append(f"SUMMARY")
        output.append("="*80)
        output.append(f"Total Endpoints Scanned: {total_endpoints}")
        output.append(f"Total Vulnerabilities Found: {total_vulnerabilities}")
        output.append("="*80 + "\n")
        
        return "\n".join(output)
    
    def generate_json_report(self, results: Dict, filepath: str):
        """
        Genera reporte en formato JSON
        """
        report_data = {
            'timestamp': self.timestamp,
            'summary': {
                'total_endpoints': len(results),
                'total_vulnerabilities': 0,
                'vulnerable_endpoints': 0
            },
            'endpoints': []
        }
        
        for endpoint, endpoint_data in results.items():
            url = endpoint_data.get('url', endpoint)
            scan_results = endpoint_data.get('results', [])
            
            endpoint_report = {
                'endpoint': endpoint,
                'url': url,
                'vulnerabilities': []
            }
            
            for result in scan_results:
                detector_result = result.get('detector_result', {})
                if detector_result.get('vulnerable', False):
                    vuln_data = {
                        'parameter': result.get('param', 'N/A'),
                        'payload': detector_result.get('payload', 'N/A'),
                        'payload_type': detector_result.get('payload_type', 'N/A'),
                        'vulnerability_type': detector_result.get('vulnerability_type', 'N/A'),
                        'confidence': detector_result.get('confidence', 'low'),
                        'status_code': result.get('status_code', 0),
                        'response_time': result.get('time', 0.0),
                        'response_length': len(result.get('text', '')),
                        'evidence': detector_result.get('evidence', []),
                        'indicators': detector_result.get('indicators', {}),
                        'ml_prediction': result.get('ml_result', {})
                    }
                    endpoint_report['vulnerabilities'].append(vuln_data)
            
            if endpoint_report['vulnerabilities']:
                report_data['summary']['vulnerable_endpoints'] += 1
                report_data['summary']['total_vulnerabilities'] += len(endpoint_report['vulnerabilities'])
            
            report_data['endpoints'].append(endpoint_report)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] JSON report saved to {filepath}")
    
    def generate_html_report(self, results: Dict, filepath: str):
        """
        Genera reporte HTML profesional
        """
        html_content = self._generate_html_content(results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to {filepath}")
    
    def _generate_html_content(self, results: Dict) -> str:
        """Genera el contenido HTML completo"""
        
        # Calcular estadísticas
        total_endpoints = len(results)
        total_vulnerabilities = 0
        vulnerable_endpoints = 0
        
        for endpoint_data in results.values():
            scan_results = endpoint_data.get('results', [])
            vuln_count = sum(1 for r in scan_results 
                           if r.get('detector_result', {}).get('vulnerable', False))
            if vuln_count > 0:
                vulnerable_endpoints += 1
                total_vulnerabilities += vuln_count
        
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
        .summary-card p {{
            font-size: 0.9em;
            opacity: 0.9;
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
        .vulnerability.medium {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        .vulnerability.low {{
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }}
        .vulnerability.potential {{
            background: #fff8e1;
            border-left-color: #ff9800;
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
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        .evidence ul {{
            margin-left: 20px;
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
        .badge.medium {{
            background: #ffc107;
            color: #333;
        }}
        .badge.low {{
            background: #17a2b8;
            color: white;
        }}
        .badge.type {{
            background: #6c757d;
            color: white;
        }}
        .endpoint-section {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .metadata {{
            color: #6c757d;
            font-size: 0.9em;
            margin: 10px 0;
        }}
        .ml-info {{
            background: #e7f3ff;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 3px solid #2196F3;
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
        table tr:hover {{
            background: #f5f5f5;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SQL Injection Scanner - Security Report</h1>
        <p class="metadata">Generated: {self.timestamp}</p>
        
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
        
        # Agregar detalles por endpoint
        for endpoint, endpoint_data in results.items():
            url = endpoint_data.get('url', endpoint)
            scan_results = endpoint_data.get('results', [])
            
            # Incluir vulnerabilidades confirmadas y potenciales
            vulnerabilities = [r for r in scan_results 
                             if r.get('detector_result', {}).get('vulnerable', False)]
            
            # También incluir respuestas con confianza media/alta aunque no estén marcadas como vulnerables
            potential_vulns = [r for r in scan_results 
                             if not r.get('detector_result', {}).get('vulnerable', False)
                             and r.get('detector_result', {}).get('confidence') in ['medium', 'high']]
            
            # Combinar ambas listas
            all_issues = vulnerabilities + potential_vulns
            
            if all_issues:
                html += f"""
        <div class="endpoint-section">
            <h2>📍 {escape(endpoint)}</h2>
            <p class="metadata">URL: <code>{escape(url)}</code></p>
            <p class="metadata">Vulnerabilities Found: {len(vulnerabilities)}</p>
            <p class="metadata">Potential Issues: {len(potential_vulns)}</p>
"""
                
                for result in all_issues:
                    detector_result = result.get('detector_result', {})
                    param = result.get('param', 'N/A')
                    payload = detector_result.get('payload', 'N/A')
                    vuln_type = detector_result.get('vulnerability_type', 'unknown')
                    confidence = detector_result.get('confidence', 'low')
                    evidence = detector_result.get('evidence', [])
                    ml_result = result.get('ml_result', {})
                    is_vulnerable = detector_result.get('vulnerable', False)
                    
                    # Determinar clase CSS
                    vuln_class = 'vulnerability'
                    if is_vulnerable:
                        vuln_class += f' {confidence}'
                    else:
                        vuln_class += ' potential'
                    
                    # Título según si es vulnerable o potencial
                    title_prefix = "[!] VULNERABLE" if is_vulnerable else "[?] POTENTIAL"
                    
                    html += f"""
            <div class="{vuln_class}">
                <h3>{title_prefix} - Parameter: <code>{escape(param)}</code></h3>
                <div class="payload">
                    <strong>Payload:</strong> {escape(payload)}
                </div>
                <span class="badge type">{escape(vuln_type) if vuln_type != 'unknown' else 'suspicious'}</span>
                <span class="badge {confidence}">Confidence: {confidence.upper()}</span>
                
                <div class="evidence">
                    <strong>Evidence:</strong>
                    <ul>
"""
                    for ev in evidence:
                        html += f"                        <li>{escape(str(ev))}</li>\n"
                    
                    html += """                    </ul>
                </div>
"""
                    
                    # --- NUEVO BLOQUE: PROOF OF CONCEPT / SNIPPET ---
                    indicators = detector_result.get('indicators', {})
                    proof_html = ""
                    
                    # Caso 1: Error Based - Mostrar el error exacto
                    if 'error_snippet' in indicators:
                        snippet = indicators['error_snippet']
                        proof_html = f"""
                        <div class="evidence" style="background: #fff0f0; border-left: 4px solid #dc3545;">
                            <strong>🔎 Smoking Gun (SQL Error Found):</strong>
                            <pre style="background: #333; color: #fff; padding: 10px; border-radius: 4px; overflow-x: auto; margin-top: 5px;">...{escape(snippet)}...</pre>
                        </div>
                        """
                    
                    # Caso 2: Boolean/Time/Union - Mostrar preview de respuesta
                    elif 'response_preview' in indicators:
                        preview = indicators['response_preview']
                        proof_html = f"""
                        <div class="evidence" style="background: #f8f9fa; border-left: 4px solid #6c757d;">
                            <strong>📄 Response Preview (First 300 chars):</strong>
                            <pre style="background: #fff; border: 1px solid #ddd; padding: 10px; color: #555; font-size: 0.9em; overflow-x: auto; margin-top: 5px;">{preview}...</pre>
                        </div>
                        """
                    
                    # Caso 3: Inyección de datos (Filtered Query detectada)
                    elif 'filtered_query' in indicators:
                         query = indicators['filtered_query']
                         proof_html = f"""
                        <div class="evidence" style="background: #fff3cd; border-left: 4px solid #ffc107;">
                            <strong>⚠️ Leaked Query:</strong>
                            <pre style="background: #333; color: #f1c40f; padding: 10px;">{escape(query)}</pre>
                        </div>
                        """

                    html += proof_html
                    # ------------------------------------------------
                    
                    if ml_result and ml_result.get('prediction') != 'unknown':
                        ml_prob = ml_result.get('probability', 0.0)
                        html += f"""
                <div class="ml-info">
                    <strong>🤖 ML Prediction:</strong> {escape(ml_result.get('prediction', 'unknown'))} 
                    (Probability: {ml_prob:.1%}, Confidence: {escape(ml_result.get('confidence', 'low'))})
                </div>
"""
                    
                    # Información técnica
                    resp_length = len(result.get('text', ''))
                    base_length = detector_result.get('base_length', 0)
                    length_diff = abs(resp_length - base_length)
                    html_analysis = detector_result.get('indicators', {}).get('html_analysis', {})
                    similarity = html_analysis.get('similarity', 1.0) if html_analysis else 1.0
                    
                    html += f"""
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Status Code</td>
                        <td>{result.get('status_code', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td>Response Time</td>
                        <td>{result.get('time', 0.0):.2f}s</td>
                    </tr>
                    <tr>
                        <td>Response Length</td>
                        <td>{resp_length} bytes</td>
                    </tr>
                    <tr>
                        <td>Base Length</td>
                        <td>{base_length} bytes</td>
                    </tr>
                    <tr>
                        <td>Length Difference</td>
                        <td>{length_diff} bytes ({((length_diff/base_length)*100) if base_length > 0 else 0:.1f}%)</td>
                    </tr>
                    <tr>
                        <td>HTML Similarity</td>
                        <td>{similarity:.2%}</td>
                    </tr>
                </table>
"""
                    
                    # Descripción de la vulnerabilidad
                    from sqli_detector import SQLInjectionDetector
                    detector = SQLInjectionDetector()
                    description = detector.get_vulnerability_description(vuln_type)
                    html += f"""
                <div class="evidence">
                    <strong>Vulnerability Description:</strong>
                    <p>{escape(description)}</p>
                </div>
            </div>
"""
                
                html += """
            </div>
        </div>
"""
        
        html += """
        <div class="footer">
            <p>Generated by SQL Injection Scanner</p>
            <p>This report is for security testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html