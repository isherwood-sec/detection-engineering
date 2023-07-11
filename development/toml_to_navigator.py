import tomllib
import os

techniques = {}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                for threat in alert['rule']['threat']:
                    technique_id = str(threat['technique'][0]['id'])
                    tactic = str(threat['tactic']['name'])

                    if technique_id not in techniques:
                        obj = {'technique_id': technique_id, 'tactic': tactic, 'count': 1}
                        techniques[technique_id] = obj
                    else:
                        techniques[technique_id]['count'] += 1
                    
                    if 'subtechnique' in threat['technique'][0]:
                        subtechnique = threat['technique'][0]['subtechnique'][0]['id']
                        if subtechnique not in techniques:
                            obj = {'technique_id': subtechnique, 'tactic': tactic, 'count': 1}
                            techniques[subtechnique] = obj
                        else:
                            techniques[subtechnique]['count'] += 1


beginning = """{
	"name": "Custom Detections",
	"versions": {
		"attack": "13",
		"navigator": "4.8.2",
		"layer": "4.4"
	},
	"domain": "enterprise-attack",
	"description": "",
	"filters": {
		"platforms": [
			"Linux",
			"macOS",
			"Windows",
			"Network",
			"PRE",
			"Containers",
			"Office 365",
			"SaaS",
			"Google Workspace",
			"IaaS",
			"Azure AD"
		]
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": false,
		"showName": true,
		"showAggregateScores": false,
		"countUnscored": false
	},
	"hideDisabled": false,
    """

end = """
    ],
	"gradient": {
		"colors": [
			"#ff6666ff",
			"#ffe766ff",
			"#8ec843ff"
		],
		"minValue": 0,
		"maxValue": 3
	},
	"legendItems": [],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": false,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": true,
	"selectSubtechniquesWithParent": false
}"""

counter = 0
total_techniques = 0

for technique in techniques:
    total_techniques += 1

output_path = "metrics/navigator.json"

outF = open(output_path, "w")
outF.write(beginning)
outF.write("\"techniques\": [")

for key in techniques:
    counter += 1
    technique_id = techniques[key]['technique_id']
    count = str(techniques[key]['count'])
    tactic = techniques[key]['tactic'].lower()
    outF.write("\n\t\t{")
    outF.write("\n\t\t\t\"techniqueID\": \"" + technique_id + "\",")
    outF.write("\n\t\t\t\"tactic\": \"" + tactic + "\",")
    outF.write("\n\t\t\t\"score\": " + count + ",")
    outF.write("\n\t\t\t\"color\": \"\""",")
    outF.write("\n\t\t\t\"comment\": \"\""",")
    outF.write("\n\t\t\t\"enabled\": true,")
    outF.write("\n\t\t\t\"metadata\": [],")
    outF.write("\n\t\t\t\"links\": [],")
    outF.write("\n\t\t\t\"showSubtechniques\": false")

    if counter != total_techniques:
        outF.write("\n\t\t},")
    else:
        outF.write("\n\t\t}")

outF.write(end)
outF.close()