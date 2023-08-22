import tomllib
import os
import datetime
from dateutil.relativedelta import relativedelta

list = {}

today = datetime.date.today()
current_month = str(today).split("-")[0] + "-" + str(today).split("-")[1]
one_month_ago = str(today - relativedelta(months=1)).split("-")[0] + "-" + str(today - relativedelta(months=1)).split("-")[1]
two_months_ago = str(today - relativedelta(months=2)).split("-")[0] + "-" + str(today - relativedelta(months=2)).split("-")[1]

current = {}
one_month = {}
two_months = {}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                date = alert['metadata']['creation_date']
                name = alert['rule']['name']
                author = alert['rule']['author']
                risk_score = alert['rule']['risk_score']
                severity = alert['rule']['severity']
                filtered_object_array = []

                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for threat in alert['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']

                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else:
                            tactic = "none"

                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"

                        technique = technique_id + " - " + technique_name
                        subtech = subtechnique_id + " - " + subtechnique_name

                        obj = {'tactic': tactic, 'technique': technique, 'subtech': subtech, 'subtech': subtech}
                        filtered_object_array.append(obj)
                obj = {'name': name, 'date': date, 'author': author, 'risk_score': risk_score, 'severity': severity, 'mitre': filtered_object_array}
                
                year = date.split("/")[0]
                month = date.split("/")[1]
                date_compare = year + "-" + month
                
                if date_compare == current_month:
                    current[file] = obj
                elif date_compare == one_month_ago:
                    one_month[file] = obj
                elif date_compare == two_months_ago:
                    two_months[file] = obj

                list[file] = obj

output_path = "metrics/recentdetections.md"

outF = open(output_path, "w")
outF.write("# Detection Report\n")

outF.write("## Current Month\n")
outF.write("### New Alerts\n")
outF.write("| Alert | Date | Author | Risk Score | Severity |\n")
outF.write("| --- | --- | --- | --- | --- |\n")
# Current Month
for line in current.values():
    date = line['date']
    name = line['name']
    author = str(line['author']).replace(",",";")
    risk_score = str(line['risk_score'])
    severity = line['severity']

    outF.write("|" + name + "|" + date + "|" + author + "|" + risk_score  + "|" + severity + "|\n")

outF.write("## Last Month\n")
outF.write("### Alerts\n")
outF.write("| Alert | Date | Author | Risk Score | Severity |\n")
outF.write("| --- | --- | --- | --- | --- |\n")

# Last Month
for line in one_month.values():
    date = line['date']
    name = line['name']
    author = str(line['author']).replace(",",";")
    risk_score = str(line['risk_score'])
    severity = line['severity']


    outF.write("|" + name + "|" + date + "|" + author + "|" + risk_score  + "|" + severity + "|\n")

outF.write("## Two Months Ago\n")
outF.write("### Alerts\n")
outF.write("| Alert | Date | Author | Risk Score | Severity |\n")
outF.write("| --- | --- | --- | --- | --- |\n")
# Two Months
for line in two_months.values():
    date = line['date']
    name = line['name']
    author = str(line['author']).replace(",",";")
    risk_score = str(line['risk_score'])
    severity = line['severity']


    outF.write("|" + name + "|" + date + "|" + author + "|" + risk_score  + "|" + severity + "|\n")

outF.close()


                