import json
from datetime import datetime

def generate_report(findings):
    severity_count={
       "CRITICAL":0,
        "HIGH":0,
        "MEDIUM":0,
        "LOW":0
    }
    for finding in findings:
        severity_count[finding["severity"]]+=1
    if severity_count ["CRITICAL"] > 0 or severity_count['HIGH'] > 0:
        status = "⚠️ High Risk"
    elif severity_count['MEDIUM'] > 0:
        status = "⚠️ Medium Risk"
    else:
        status = "✅ Low Risk"
    scan_time=datetime.now().strftime("%d %B %Y, %I:%M:%S %p")
    with open("reports/report.json","w",encoding='utf-8') as report:
        json.dump(findings,report,indent=4,default=str)
    with open("reports/report.html","w",encoding="utf-8") as report:
        report.write(f"""
                     <html lang="en">
                     <head>
                     <meta charset="UTF-8">
                     <title>CloudGuard Report</title>
                     <style>
                     body{{
                         font-family:Arial,sans-serif;
                         margin:auto;
                         background:#eef2f5;
                         max-width:1400px;
                         padding:30px;
                     }}
                     h1{{
                         text-align:center;
                         color:#2c3e50;
                     }}
                     .summary{{
                        background:#f8f9fa;
                        border:1px solid #ddd;
                        border-radius:8px;
                        padding:20px;
                        margin-bottom:25px;
                        box-shadow:0 2px 10px rgba(0,0,0,0.1);
                     }}
                     .summary p{{
                     margin:10px 0;
                     }}
                     h2{{
                        color:#2c3e50;
                     }}
                     table{{
                         width:100%;
                         border-collapse:collapse;
                         border-radius:8px;
                         overflow:hidden;
                         box-shadow:0 2px 10px rgba(0,0,0,0.1);
                     }}
                     th,td{{
                         border:1px solid black;
                         padding: 14px;
                         text-align:left;
                     }}
                     th{{
                         background-color:#2c3e50;
                         color:white;
                     }}
                     tr:nth-child(even){{
                         background:#f7f7f7;
                     }}
                     tr:hover{{
                         background:#dfefff;
                     }}
                     td{{
                         vertical-align:top;
                         word-break:break-word;
                     }}
                     td.region {{
                         text-align:center;
                     }}
                     </style>
                     </head>
                     <body>
                     <h1> CloudGuard Security Report </h1>
                     <hr>
                     <div class="summary">
                     <p><strong> Scan Time:</strong> {scan_time}</p>
                     <p><strong>Total Findings:</strong>{len(findings)}</p>
                     <p><strong>Overall Status:</strong>{status}</p>
                     <p><strong>Critical:</strong>{severity_count["CRITICAL"]}</p>
                     <p><strong>High:</strong>{severity_count["HIGH"]}</p>
                     <p><strong>Medium:</strong>{severity_count["MEDIUM"]}</p>
                     <p><strong>Low:</strong>{severity_count["LOW"]}</p>

                     </div>
                     <hr>
                     <h2> Findings</h2>
                     <table>
                     <tr>
                        <th>Rule ID </th>
                        <th>Service </th>
                        <th>Region</th>
                        <th>Resource </th>
                        <th>Severity</th>
                        <th>Finding </th>
                        <th>Recommendation </th>
                     </tr>
                     """)
        severity_order={
         "CRITICAL": 0,
         "HIGH": 1,
         "MEDIUM": 2,
         "LOW": 3   
        }
        sorted_findings=sorted(findings,key=lambda x: severity_order[x["severity"]])
        for finding in sorted_findings:
            severity=finding["severity"]
            if severity=="CRITICAL":
                color="#8B0000"
            elif severity=="HIGH":
                color="#E53935"
            elif severity=="MEDIUM":
                color="#FB8C00"
            else:
                color="#43A047"
            report.write(f"""
                        <tr>
                         <td>{finding["rule_id"]}</td>
                         <td>{finding["service"]}</td>
                         <td>{finding["region"]}</td>
                         <td>{finding["resource"]}</td>
                         <td style="color:{color};font-weight:bold;">{severity}</td>
                         <td>{finding["finding"]}</td>
                         <td>{finding["recommendation"]}</td>
                        </tr>  
                        """)
        report.write("""
                    </table>
                    <hr>
                    <p style="text-align:center;color:gray;font-size:14px;">
                    Generated by <strong>CloudGuard v1.0</strong>
                    </p>
                    </body>
                    </html>
                    """)
        