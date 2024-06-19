#!/usr/bin/env python
import sys,json,io
import pandas as pd
from argparse import ArgumentParser
from dynatrace_api import DynatraceApi
import logging
import logging.config
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')

parser.add_argument("-d", "--details", dest="details", help="Fetch the details for each security problem (takes longer)", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
showDetails = args.details
verifySSL = not args.insecure

debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)


def writeResultToFile(filename, result):
    df = pd.json_normalize(result)
    df.to_csv(filename,sep=';', index=False, quotechar="'", encoding='utf-8')
    print()
    print('results stored under '+filename)

def writeDirectlyToFile(filename, result):
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(f"securityProblemId;pg_id,processGroupId;processFilePath;affectedEntitiesId;displayName\n")
        for item in result:
            file.write(f"{item}\n")
    file.close()
    print('results stored under '+filename)

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

# retireve all security problems
securityProblems = dynatraceApi.getSecurityProblems()

# if the details flag is set, retrieve the details for every security problem
# write result to a CSV file
securityProblemDetails = []
securityRemediationEvents = []
remediationItems = []
remEvent = []
csv_buffer = io.StringIO()
securityRemediationEvents = io.StringIO()
for secP in securityProblems:
    securityProblemDetail = dynatraceApi.getSecurityProblemDetails(secP["securityProblemId"])
    securityProblemDetails.append(securityProblemDetail)
    remediationItems = dynatraceApi.getRemediationItems(secP["securityProblemId"])
    for remId in remediationItems["remediationItems"]:
        if remId["vulnerabilityState"] == "VULNERABLE":
          pgId = remId["id"]
          securityRemediationEvent = dynatraceApi.getRemediationItemEntities(secP["securityProblemId"], pgId)
          for remItem in securityRemediationEvent["remediationProgressEntities"]:
            for component in remItem["vulnerableComponents"]:
                if "loadOrigins" in component:
                  loadOrigin = f"{secP['securityProblemId']};{pgId};{component['loadOrigins']};{remItem['id']};{remItem['name']}"
                  # Keep adding more fields as required to line 75 to append and create as a single file with all details.
                  remEvent.append(loadOrigin)
writeResultToFile('securityProblemDetails.csv', securityProblemDetails)
writeDirectlyToFile('securityRemediationDetails.csv', remEvent)
writeResultToFile('securityProblems.csv', securityProblems)
