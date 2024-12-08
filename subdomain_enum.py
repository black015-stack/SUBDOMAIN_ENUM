import argparse
import asyncio
import aiohttp
import time
import json
import csv
import os
import re
import logging
import redis
from aiodns import DNSResolver
from aiohttp import ClientSession, ClientError, ClientResponseError, ServerTimeoutError
from celery import Celery
from sklearn.ensemble import IsolationForest
from prometheus_client import start_http_server, Counter
import boto3
from botocore.exceptions import ClientError
import requests
from time import sleep
from tqdm import tqdm  # Added import for tqdm
import socket  # Added missing import for socket
from loguru import logger
import threading  # Added for thread-safe logging

# Initialize Celery and Redis
app = Celery('subdomain_enum', broker='redis://localhost:6379/0')
cache = redis.StrictRedis(host='localhost', port=6379, db=0)

# Logging Setup with Structured Logging
if not os.path.exists("logs"):
    os.makedirs("logs")
logger.add("logs/{time}.log", format="{time} {level} {message}", level="INFO", rotation="1 MB", retention="10 days")

# Constants for Rate Limiting
ONE_MINUTE = 60

# Prometheus Metrics for Centralized Monitoring
subdomain_request_count = Counter('subdomain_requests_total', 'Total number of subdomain requests')
start_http_server(8000)  # Start the Prometheus server

# Regex for Domain Validation
DOMAIN_REGEX = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$"

# Validate Domain Format
def is_valid_domain(domain):
    return re.match(DOMAIN_REGEX, domain)

# Distributed Task Queue for Subdomain Resolution
@app.task
def resolve_subdomain_task(subdomain, protocols, retries, delay, user_agents, timeout, proxy):
    # Use asyncio.run to handle async functions in Celery
    return asyncio.run(resolve_subdomain(subdomain, protocols, retries, delay, user_agents, timeout, proxy))

# Asynchronous DNS Resolution
async def resolve_dns(subdomain, resolver):
    try:
        await resolver.gethostbyname(subdomain, socket.AF_INET)
        return True
    except Exception as e:
        logger.error(f"DNS resolution failed for {subdomain}: {e}")
        return False

# Perform HTTP Request to Resolve Subdomain
async def resolve_subdomain(subdomain, protocols, retries, delay, user_agents, timeout, proxy):
    results = []
    for protocol in protocols:
        url = f"{protocol}://{subdomain}"
        headers = {"User-Agent": user_agents[0]}
        attempts = 0

        while attempts < retries:
            try:
                async with ClientSession() as session:
                    async with session.head(url, headers=headers, timeout=timeout, proxy=proxy) as response:
                        if response.status < 400:
                            results.append({"subdomain": subdomain, "status": "Resolved", "code": response.status})
                            break
            except (ClientError, ClientResponseError, ServerTimeoutError) as e:
                logger.warning(f"Error resolving {subdomain}: {e}")
                attempts += 1
                await asyncio.sleep(delay / 1000)
                delay *= 2  # Exponential backoff
            except Exception as e:
                logger.error(f"Unexpected error for {subdomain}: {e}")
                attempts += 1
                await asyncio.sleep(delay / 1000)
                delay *= 2  # Exponential backoff
        else:
            results.append({"subdomain": subdomain, "status": "Failed"})
    return results or [{"subdomain": subdomain, "status": "No results"}]

# Caching Subdomain Resolutions
def cache_resolution(subdomain, resolved_ip):
    cache.set(subdomain, resolved_ip)

# Machine Learning Anomaly Detection
def detect_anomalies(data):
    model = IsolationForest(n_estimators=100)
    model.fit(data)
    return model.predict(data)

# Fetch Threat Intelligence from Shodan API
def fetch_shodan_info(subdomain, api_key):
    url = f"https://api.shodan.io/dns/resolve?hostnames={subdomain}&key={api_key}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        logger.error(f"Shodan API Error for {subdomain}, Status Code: {response.status_code}")
    except Exception as e:
        logger.error(f"Error fetching Shodan info for {subdomain}: {e}")
    return None

# Zero Trust Architecture for Secret Management
def get_secret(secret_name):
    client = boto3.client('secretsmanager', region_name="us-east-1")
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except ClientError as e:
        logger.error(f"Error retrieving secret: {e}")
        return None

# Worker for Subdomain Processing (Celery)
async def process_subdomains(subdomains, protocols, retries, delay, user_agents, output_file, max_concurrent, timeout, proxy, shodan_api_key):
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async with ClientSession() as session:
        async def sem_task(subdomain):
            async with semaphore:
                dns_result = await resolve_dns(subdomain, DNSResolver())
                subdomain_info = await resolve_subdomain(subdomain, protocols, retries, delay, user_agents, timeout, proxy)
                shodan_info = await fetch_shodan_info(subdomain, shodan_api_key)
                return {
                    "subdomain": subdomain,
                    "dns_resolved": dns_result,
                    "http_results": subdomain_info,
                    "shodan_info": shodan_info
                }

        tasks = [sem_task(subdomain) for subdomain in subdomains]
        for coro in tqdm.as_completed(tasks, total=len(tasks), desc="Processing Subdomains"):
            result = await coro
            results.append(result)
            save_incremental_result(output_file, result)
    return results

# Save Results Incrementally to File (CSV/JSON)
def save_incremental_result(output_file, result):
    try:
        if not os.path.exists(os.path.dirname(output_file)):
            os.makedirs(os.path.dirname(output_file))

        if output_file.endswith(".csv"):
            with open(output_file, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["subdomain", "dns_resolved", "http_results", "shodan_info"])
                writer.writerow(result)
        elif output_file.endswith(".json"):
            with open(output_file, 'a') as jsonfile:
                json.dump(result, jsonfile, indent=4)
                jsonfile.write("\n")
    except Exception as e:
        logger.error(f"Error saving result: {e}")

# Load Subdomains from File
def load_subdomains(filename):
    subdomains = []
    if not os.path.exists(filename):
        logger.error(f"File {filename} does not exist.")
        return subdomains
    with open(filename, 'r') as file:
        subdomains = [line.strip() for line in file.readlines() if line.strip()]
    return subdomains

# Main Entry Point for the Application
async def main():
    parser = argparse.ArgumentParser(description="Advanced Subdomain Enumeration Tool")
    parser.add_argument('-f', '--file', required=True, help="File containing subdomains to test")
    parser.add_argument('-o', '--output', required=True, help="Output file for results (CSV or JSON)")
    parser.add_argument('--shodan-api-key', required=True, help="Shodan API key")
    parser.add_argument('-p', '--protocols', default=["http", "https"], nargs='+', help="Protocols to test")
    args = parser.parse_args()

    subdomains = load_subdomains(args.file)
    if not subdomains:
        logger.error("No valid subdomains found to process.")
        return

    await process_subdomains(
        subdomains,
        protocols=args.protocols,
        retries=3,
        delay=1000,
        user_agents=["Mozilla/5.0"],
        output_file=args.output,
        max_concurrent=10,
        timeout=10,
        proxy=None,
        shodan_api_key=args.shodan_api_key
    )

if __name__ == "__main__":
    asyncio.run(main())