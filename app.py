'''
1: Store your Umbrella Investigate API Token in a text file, with the API key on one line and no other information, then update the path to it.
2: Do the same for the VirusTotal API key, if you want to use it. If not or you don't have one, this will still work - you just won't have VirusTotal results.
3: Run with: python3 app.py
4: Go to http://127.0.0.1:5000
5: Enter your domains and look them up
'''
import time, requests, json
from datetime import datetime, timedelta
import tldextract as tld    # Extract domain elements from a domain name
from flask import Flask, request, render_template
from investigate import Investigate

investigate_api_key = 'path/to/yourUmbrellaInvestigateAPIkey.txt'   # CHANGE THIS
virustotal_api_key = 'path/to/yourVirusTotalAPIkey.txt'             # CHANGE THIS

with open(investigate_api_key) as investigate_api_key:
    token = investigate_api_key.read()
    api_key = token.rstrip()
    inv = Investigate(api_key)

with open(virustotal_api_key) as api_key:
    token = api_key.read()
    vt_api_key = token.rstrip()

app = Flask(__name__)

def validate_domain(domain):    # check if the domain is really a domain
    url_components = tld.extract(domain)
    if url_components.suffix == "":
        return False
    else:
        return True

def vt_results(domain):
    vt = {}
    urls = []
    domain_report_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    url_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  OpenDNS research "}
    params = { 'apikey' : vt_api_key, 'resource': domain}

    try:
        url_reports_request = requests.post(url_report_url, params=params, headers = headers)
        url_reports_report = url_reports_request.json()
        vt['positivescans'] = url_reports_report["positives"]
        vt['total_scans'] = url_reports_report["total"]
    except KeyError:
        pass
    return vt

def process_domains(domains):
    results = []
    not_domains_list = []   # For entered items that aren't domains
    failed_domains_list = []    # for entered items that are also not domains
    for domain in domains:
        try:
            domain = str(domain.replace('[.]','.')) # look for common safeties and remove them
            if 'http' in domain:
                domain = domain.replace('http://','')   # in case anyone enters a URL
                domain = domain.replace('https://','')   # in case anyone enters a URL
            if validate_domain(domain) == True: # Take apart the domain and make sure it's a domain (see function if needed)
                data = {}   # Dictionary to hold results for sending to the Jinja template
                domain = domain.strip() # remove any random whitespace
                data['domain'] = domain # add domain to the data dictionary
                _firstlevel = tld.extract(domain)   # get the root of the domain for other lookups
                rootdomain = "{}.{}".format(_firstlevel.domain,_firstlevel.suffix)
                ####### Get potentially malicious samples identified by ThreatGrid from the Investigate API
                try:
                    threat_scores = []
                    samples = inv.samples(domain)   # the Investigate lookup for the Samples endpoint

                    sample_results = (samples['samples'])
                    for i in sample_results:
                        threat_scores.append(i['threatScore'])

                    data['total_malicious_samples'] = samples['totalResults']
                    data['malicious_samples_average_threat_score'] = sum(threat_scores) / len(threat_scores)
                except:
                    data['total_malicious_samples'] = 'none'
                    data['malicious_samples_average_threat_score'] = 'n/a'

                ####### Popularity
                
                try:
                    security = inv.security(rootdomain) # root domain popularity, Investigate security endpoint
                    domain_as_entered_security = inv.security(domain)   # domain as entered popularity, Investigate security endpoint
                    data['popularity'] = int(domain_as_entered_security["popularity"])
                    data['root_popularity'] = int(security["popularity"])    # add popularity to data
                    data['dga_score'] = security["dga_score"]    # get dga score
                except:
                    data['popularity'] = 'none'
                    data['dga_score'] = 'none'

                ####### Whois (nameservers are in here)
                try:
                    whois = inv.domain_whois(domain) # Investigate whois endpoint
                    data['nameservers'] = whois['nameServers']  # add nameservers to data
                except:
                    data['nameservers'] = ['none']
                try:
                    whois = inv.domain_whois(rootdomain) # Investigate security endpoint lookup for the root domain
                    data['nameservers'] = whois['nameServers']  # add nameservers to data
                except:
                    data['nameservers'] = ['none']
                ####### Query Vol
                query_results,data['highest_query_30_days'], data['total_queries_thirty_days'] = get_query_count(domain)   # Get queries for mini graphs (sparklines)
                data['query_results'] = ", ".join(str(i) for i in query_results) # Query results, for the sparkline graph. 
                ####### Content categories
                try:
                    cat = inv.categorization(domain, labels=True) # Investigate content categorization endpoint
                
                    for i in cat:
                        data['content_categories'] = cat[i]['content_categories']
                except:
                    data['content_categories'] = 'none'

                ####### VT Lookup
                try:
                    vt_domain_report = vt_results(domain)   # Lookup data in Virustotal if you entered your API key in the beginning of the script. If not, don't worry as there's an exception a couple lines further
                    data['vt_positivescans'] = vt_domain_report['positivescans']
                    data['vt_totalscans'] = vt_domain_report['total_scans']
                except:
                    data['vt_positivescans'] = 0
                    data['vt_totalscans'] = 0
                results.append(data)    # add the dict results for the domain to the results list, which will be displayed using the Jinja template
            
            else:   # Add non-domains to not_domains_list
                if len(domain) == 0:
                    pass
                else:
                    not_domains_list.append(domain)  # for items entered that aren't domains (mistakes)
        except: # Add failed domains to failed_domains_list
            failed_domains_list.append(domain)

    return(results,not_domains_list, failed_domains_list)

def get_query_count(domain):    # Get queries for mini graphs
    time_and_querycount = []
    data = inv.domain_volume(domain, start=timedelta(days=30), stop=timedelta(days=0), match="exact")
    max_queries_thirty_days = '{0:,d}'.format(max(data['queries']))
    total_queries_thirty_days = '{0:,d}'.format(sum(data['queries']))
    if 'queries' in data:
        queries = data['queries']
        # Assign an hour to each time:
        epoch_start = data['dates'][0]
        epoch_end = data['dates'][1]
        end =  time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_end/1000.))
        timestamp = datetime.strptime((time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch_start/1000.))),'%Y-%m-%d %H:%M:%S') # convert epoch time and then convert to datetime object
        timestamps = []
        timestamps.append(timestamp.strftime('%Y-%m-%d %H:%M:%S'))
        for each_count in queries:
            timestamp = timestamp + timedelta(minutes=60) # add an hour
            timestamp_string = timestamp.strftime('%Y-%m-%d %H:%M:%S') # Convert back to string
            timestamps.append(timestamp_string)
        time_and_querycount = zip(timestamps[:-1],queries)
    metrics = []
    for k, v in time_and_querycount:
        # metrics_line = {'value':v,'date':k}   # used if using https://metricsgraphicsjs.org/, which is not the case for the sparklines in this app
        metrics.append(v)
    return(metrics, max_queries_thirty_days, total_queries_thirty_days)

################# ROUTES FOR FLASK
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/domains_lookup', methods=['GET','POST'])
def domains_lookup():
    domains = request.form['textbox']
    if ',' in domains:
        domains = domains.split(',')
    else:
        domains = domains.split('\r\n')
    data,notdomains,faileddomains = process_domains(domains)
    return render_template('results.html',data=data, notdomains=notdomains, faileddomains=faileddomains)

app.run(host='127.0.0.1', port=5000, debug=True)