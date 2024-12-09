Step 1: Install Dependencies

    Ensure Python 3.8+ is installed.
    Install the required libraries:

    pip install aiohttp redis aiodns celery scikit-learn prometheus-client boto3 requests tqdm loguru

Step 2: Prepare Input File

    Create a text file (e.g., subdomains.txt) containing a list of subdomains, one per line:

    example.com
    sub.example.com
    test.example.com

Step 3: Start Redis and Celery

    Start Redis server:

redis-server

Start Celery worker:

    celery -A subdomain_enum worker --loglevel=info

Step 4: Run the Tool

    Use the command-line interface:

    python subdomain_enum.py -f subdomains.txt -o output.json --shodan-api-key YOUR_SHODAN_API_KEY

    Parameters:
        -f: Input file containing subdomains to test.
        -o: Output file to save results (CSV or JSON format).
        --shodan-api-key: Your Shodan API key for threat intelligence.

Step 5: Monitor Progress

    Progress will display in the terminal via the tqdm progress bar.
    Logs will be saved in the logs/ directory.

Step 6: Review Results

    Results will be saved in the specified output file. Example formats:
        JSON:

{
  "subdomain": "example.com",
  "dns_resolved": true,
  "http_results": [
    {"subdomain": "example.com", "status": "Resolved", "code": 200}
  ],
  "shodan_info": {...}
}

CSV:

        subdomain,dns_resolved,http_results,shodan_info
        example.com,True,"[{'subdomain': 'example.com', 'status': 'Resolved', 'code': 200}]",{...}

Step 7: Monitor with Prometheus

    The Prometheus metrics server starts at http://localhost:8000.
    Use Prometheus or Grafana to track metrics like subdomain_requests_total.
