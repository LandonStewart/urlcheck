import os
import sys
import json
import random
import urllib.parse
import argparse
import concurrent.futures
import requests
from PyFunceble import URLAvailabilityChecker
from tqdm import tqdm
import iocextract
import hyperlink
from pysafebrowsing import SafeBrowsing

URL_CHECKER = URLAvailabilityChecker(
    use_extra_rules=True,
    use_whois_lookup=True,
    use_dns_lookup=True,
    use_netinfo_lookup=True,
    use_http_code_lookup=True,
    use_reputation_lookup=True,
    do_syntax_check_first=True,
    use_whois_db=True,
)


def main():
    """Execute main flow."""
    args = build_args()
    if args.file.name == "<stdin>":
        print("Using stdin, ctrl-d to end")

    gsb = SafeBrowsing(args.gsb_api_key)
    urls = sorted(set(extract_urls(args.file)))
    if urls:
        results = gsb.lookup_urls(urls)
    else:
        raise SystemExit("No valid URLs found")

    # Check the URLs and update results{}
    with tqdm(
        total=len(results),
        colour="yellow",
        desc="URL Check Progress",
        unit=" URL",
        ncols=80,
    ) as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            future_to_process = {
                executor.submit(get_url_status, url): url
                for url, values in results.items()
            }
            for future in concurrent.futures.as_completed(future_to_process):
                url = future_to_process[future]
                results[url].update({"status": future.result()})
                if args.urlscan_api_key:
                    results[url].update(
                        {"urlscan": get_urlscan(url, args.urlscan_api_key)}
                    )
                pbar.update(1)

    report(results)


def report(results):
    """Print report."""
    alive = 0
    output = []
    for url, values in results.items():
        parsed = urllib.parse.urlparse(url)
        if values["malicious"] and values["status"]["code"] < 400:
            alive = +1
            recommendation = f"""Remove content from {parsed.path}"""
        elif values["malicious"] and values["status"]["code"] >= 400:
            recommendation = """Request a review from Google."""
        else:
            recommendation = """None.  OK"""

        output.append(f"""\n# {obfuscate(url)}""")
        output.append(f"""+ {"Required Action:":>18} {recommendation}""")
        output.append(f"""- {"Malicious:":>18} {values["malicious"]}""")
        if "threats" in values:
            output.append(f"""- {"Threats:":>18} {", ".join(values["threats"])}""")
        if "status" in values:
            output.append(
                f"""- {"Status:":>18} {values["status"]["code"]} - {values["status"]["reason"]}"""
            )
        output.append(f"""- {"Website:":>18} {parsed.netloc}""")
        output.append(f"""- {"Path:":>18} {parsed.path}""")
        output.append(
            f"""- {"Google Status:":>18} https://transparencyreport.google.com/safe-browsing/search?url={parsed.netloc}"""
        )
        if "urlscan" in values and "result" in values["urlscan"]:
            output.append(f"""- {"URLScan:":>18} {values["urlscan"]["result"]}""")

    print("Hello,\n")

    if alive == 0:
        print(
            "This case has been closed for now since all of the URLs appear to have been disabled.  If more reports come in, however, this case will be reopened and you will be notified.\n"
        )

    print(
        "Below is a summary of the URLs related to this issue including any required actions that remain to be taken."
    )

    for line in output:
        print(line)

    print(
        "\nIf you have any questions related to this issue please respond as soon as possible.\n\nRegards,\n\n"
    )


def obfuscate(text):
    """Defang URLs and hostnames."""
    text = text.replace("http", "hxxp")
    text = text.replace(".", "[.]")
    return text


def build_args():
    """Build arguments from the command line."""
    parser = argparse.ArgumentParser(
        prog="urlcheck",
        description="Checks URLs against Google Safe Browsing and checks their status",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=open,
        help="Defaults to /dev/stdin",
        default=sys.stdin,
    )
    parser.add_argument(
        "-g",
        "--gsb_api_key",
        help="Defaults to GSB_API_KEY environment variable",
        default=os.environ.get("GSB_API_KEY"),
    )
    parser.add_argument(
        "-u",
        "--urlscan_api_key",
        help="Defaults to URLSCAN_API_KEY environment variable",
        default=os.environ.get("URLSCAN_API_KEY"),
    )
    args = parser.parse_args()

    if args.gsb_api_key is None:
        parser.error("Error: GSB_API_KEY environment variable is not set")

    if args.urlscan_api_key is None:
        print("Warning: Optional URLSCAN_API_KEY environment variable is not set")

    return args


def extract_urls(file):
    """Extract all the URLs from the text provided."""
    for url in iocextract.extract_urls(file.read(), refang=True):
        url = hyperlink.parse(url)
        yield url.normalize().to_text()


def get_urlscan(url, urlscan_api_key):
    """Execute scan at urlscan.io and retrieve the URL for the results."""
    headers = {"API-Key": urlscan_api_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    response = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers=headers,
        data=json.dumps(data),
        timeout=5,
    )
    return response.json()


def get_url_status(url):
    """Use PyFunceble to check the status of a URL's fetchability."""
    URL_CHECKER.set_subject(url)
    status = URL_CHECKER.get_status().to_dict()
    return {
        "code": status["http_status_code"],
        "reason": f"""{status["status"]} ({status["status_source"]})""",
    }
