import json

def generate_report(findings):
    with open("reports/report.json","w") as report:
        json.dump(findings,report,indent=4,default=str)
    print("report generated successfully!")