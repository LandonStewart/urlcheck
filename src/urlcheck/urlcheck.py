import os
import sys
import json
import random
import urllib.parse
import argparse
import concurrent.futures
import requests
from tqdm import tqdm
import iocextract
import hyperlink
from pysafebrowsing import SafeBrowsing


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
                executor.submit(
                    get_url_status, url, timeout=args.timeout, proxy=args.proxy
                ): url
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
    print(
        """Hello,\n\nBelow is a summary of the URLs related to this issue""",
        """including any required actions that must be taken.""",
    )

    for url, values in results.items():
        parsed = urllib.parse.urlparse(url)
        if values["status"]["code"] and values["status"]["code"] < 400:
            recommendation = f"""Remove content from {parsed.path}"""
        elif values["status"]["code"] and values["status"]["code"] >= 400:
            recommendation = """Request a review from Google."""
        else:
            recommendation = """None.  OK"""

        print(f"""\n# {obfuscate(url)}""")
        print(f"""+ {"Required Action:":>18}""", f"""{recommendation}""")
        print(f"""- {"Malicious:":>18}""", f"""{values["malicious"]}""")
        if "threats" in values:
            print(f"""- {"Threats:":>18}""", f"""{", ".join(values["threats"])}""")
        if "status" in values:
            print(f"""- {"Status:":>18}""", f"""{values["status"]}""")
        print(f"""- {"Website:":>18}""", f"""{parsed.netloc}""")
        print(f"""- {"Path:":>18}""", f"""{parsed.path}""")
        print(
            f"""- {"Google Status:":>18}""",
            """https://transparencyreport.google.com/"""
            f"""safe-browsing/search?url={parsed.netloc}""",
        )
        if "urlscan" in values and "result" in values["urlscan"]:
            print(f"""- {"URLScan:":>18}""", f"""{values["urlscan"]["result"]}""")

    print(
        """\nIf you have any questions related to this issue please respond as""",
        """soon as possible.\n\nRegards,\n\n""",
    )


def obfuscate(text):
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
    parser.add_argument(
        "-p",
        "--proxy",
        help="https proxy to use (eg. 20.229.33.75:8080)",
        default=None,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="http timeout (defaults to 5)",
        default=5,
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
    headers = {"API-Key": urlscan_api_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    response = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers=headers,
        data=json.dumps(data),
        timeout=5,
    )
    return response.json()


def get_url_status(url, timeout=5, proxy=None):
    """Return True if the URL works."""
    ua = (
        "Mozilla/5.0 (X11; Linux i686; rv:64.0) Gecko/20100101 Firefox/64.0",
        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.10; rv:62.0) Gecko/20100101 Firefox/62.0",
        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.13; ko; rv:1.9.1b2) Gecko/20081201 Firefox/60.0",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    )

    session = requests.Session()
    # Proxy stuff will go here
    try:
        response = session.head(
            url,
            timeout=timeout,
            headers={"User-Agent": random.choice(ua)},
        )
    except Exception as req_err:  # pylint: disable=broad-except
        return {"code": None, "reason": str(req_err)}
    else:
        return {"code": response.status_code, "reason": response.reason}


if __name__ == "__main__":
    main()
