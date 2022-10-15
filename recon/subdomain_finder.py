import requests
import dataclasses
import argparse
import os
import sys
import dns.resolver

from bs4 import BeautifulSoup
from rich.progress import track
from pathlib import Path

""" Types """

@dataclasses.dataclass
class Err(Exception):
  message: str

""" Request helpers """

def _request(function, url: str, allowed_response_codes: list[int], *args, **kwargs):
  response = function(url, *args, **kwargs)
  if not response.status_code in allowed_response_codes:
    raise Err("Status code %d" % response.status_code)
  return response

def get(url: str, allowed_response_codes: list[int] = [200], *args, **kwargs):
  return _request(requests.get, url, allowed_response_codes, *args, **kwargs)

def post(url: str, allowed_response_codes: list[int] = [200], *args, **kwargs):
  return _request(requests.get, url, allowed_response_codes, *args, **kwargs)

""" JSON/array helpers """

def unique(l: list | map) -> list:
  return list(set(l))

def flat_map(xs: list[list]) -> list:
  ys = []
  for x in xs:
      ys.extend(x)
  return ys

def extract_key(key: str, objs: list | map) -> list:
  return list(map(lambda x: x[key], objs))

""" Processing helpers """

def extract_subdomain(url: str):
  return url.split("://")[-1].split("/")[0].split("@")[-1].split(":")[0]

def clean_results(subdomains, domain: str):
  ending = domain
  if not domain.startswith("."):
    ending = f".{ending}"
  subdomains = list(filter(lambda x: x.endswith(ending), subdomains))
  subdomains = [subdomain.replace("*.", "") for subdomain in subdomains]
  if domain in subdomains:
    subdomains.remove(domain)
  return unique(subdomains)

""" Services """

def check_alienvault(domain: str):
  response = get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", [200, 400])
  if response.status_code == 400:
    return []
  subdomains = unique(extract_key("hostname", response.json()["passive_dns"]))
  return clean_results(subdomains, domain)

def check_certspotter(domain: str):
  response = get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", [200, 403])
  if response.status_code == 403:
    return []
  subdomains = flat_map(extract_key("dns_names", response.json()))
  return clean_results(subdomains, domain)

def check_crtsh(domain: str):
  response = get(f"https://crt.sh/?q=%.{domain}&output=json")
  subdomains = extract_key("name_value", response.json())
  return clean_results(subdomains, domain)

def check_hackertarget(domain: str):
  response = get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
  if response.text == "error invalid host":
    return []
  lines = response.text.split("\n")
  if "" in lines:
    lines.remove("")
  subdomains = list(map(lambda x: x.split(",")[0], lines))
  return clean_results(subdomains, domain)

def check_rapiddns(domain: str):
  response = get(f"https://rapiddns.io/subdomain/{domain}")
  soup = BeautifulSoup(response.text, features="html.parser")

  subdomains = []
  row = soup.find("tr")
  while row != None:
    cell = row.find_next("td")
    if cell == None:
      break
    subdomains.append(cell.text)
    row = row.find_next("tr")
  return clean_results(subdomains, domain)

def check_threatminer(domain: str):
  response = get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", [200, 404])
  if response == 404:
    return []
  subdomains = response.json()["results"]
  return clean_results(subdomains, domain)

def check_urlscan(domain: str):
  response = get(f"https://urlscan.io/api/v1/search?q={domain}")
  urls = extract_key("url", extract_key("page", response.json()["results"]))
  urls = list(filter(lambda x: domain in x, urls))
  subdomains = map(extract_subdomain, urls)
  return clean_results(subdomains, domain)

def check_webarchive(domain: str):
  response = get(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey")
  urls = response.text.split("\n")
  subdomains = list(map(extract_subdomain, urls))
  if domain in subdomains:
    subdomains.remove(domain)
  if "" in subdomains:
    subdomains.remove("")
  return clean_results(subdomains, domain)

def check_bruteforce(domain: str):
  resolver = dns.resolver.Resolver()
  resolver.timeout = 0.5 # type: ignore

  path = Path(__file__).with_name("common_subdomains.txt")
  with path.open("r") as subdomain_file:
    subdomain_list = [subdomain.strip() for subdomain in subdomain_file.read().split()]

  types = ["A", "AAAA", "CNAME", "DNSKEY", "MX", "TXT"]
  subdomains = []

  # TODO: This can probably be optimised to avoid the need for so many repeated dns requests?
  for subdomain in track(subdomain_list, description="Bruteforcing"):
    subdomain = f"{subdomain}.{domain}"
    try:
      for query_type in types:
        resolver.resolve(subdomain, query_type)
        subdomains.append(subdomain)
        break
    except dns.resolver.NXDOMAIN:
      pass
    except dns.resolver.NoAnswer:
      # Doesn't work for cloudflare domains because cloudflare doesn't follow the spec
      # subdomains.append(subdomain)
      pass
    except KeyboardInterrupt:
      exit(1)
    except:
      pass

  return subdomains

default_services = [
  ("otx.alienvault.com", check_alienvault),
  ("api.certspotter.com", check_certspotter),
  ("crt.sh", check_crtsh),
  ("api.hackertarget.com", check_hackertarget),
  ("rapiddns.io", check_rapiddns),
  ("api.threatminer.org", check_threatminer),
  ("urlscan.io", check_urlscan),
  ("web.archive.org", check_webarchive)
]

""" API """

def find_subdomains(domain: str, services, log = None):
  if log == None:
    log = lambda x: print(f"  [*] {x}")

  subdomains: set[str] = set()

  for (name, service) in services:
    try:
      if name == "bruteforce":
        log(f"Bruteforcing to search for missed subdomains")
      else:
        log(f"Searching '{name}'")
      count_before = len(subdomains)
      subdomains.update(service(domain))
      count_after = len(subdomains)
      count = count_after - count_before
      log(f"Found {count} new subdomains")
    except KeyboardInterrupt:
      exit(1)
    except Exception:
      log(f"Failed to search '{name}'")

  return list(subdomains)

""" Main """

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Enumerate subdomains of a domain.")
  parser.add_argument("domains", type=str, nargs="+", help="the domain to enumerate subdomains of")
  parser.add_argument("--include-domain", action="store_true", help="include the original domain in the list of subdomains")
  parser.add_argument("-o", "--output-dir", type=str, help="directory to save subdomain lists to")
  parser.add_argument("-b", "--bruteforce", action="store_true", help="enable the bruteforce service")
  args = parser.parse_args()

  domains = args.domains
  include_domain = args.include_domain
  output_dir = args.output_dir

  services = list(default_services)
  if args.bruteforce:
    services.append(("bruteforce", check_bruteforce))

  if output_dir != None:
    if os.path.isdir(output_dir):
      if len(list(filter(lambda x: not x.startswith("."), os.listdir(output_dir)))) != 0:
        sys.exit("error: Output directory already exists and is not empty.")
    else:
      os.mkdir(output_dir)

  sub_count = 0
  for domain in domains:
    print(f"[*] Searching for subdomains of '{domain}'")
    subdomains = set(find_subdomains(domain, services))
    if include_domain:
      subdomains.add(domain)
    count = len(subdomains)
    sub_count += count
    print()

    if output_dir == None:
      print(f"  Found {count} subdomains for {domain}:")
      print("  - " + "\n  - ".join(subdomains))
    else:
      output_file = f"{output_dir}/{domain}.txt"
      print(f"  Saved {count} subdomains to '{output_file}'")
      with open(output_file, "w") as f:
        f.write("\n".join(subdomains))
    print()

  count = len(domains)
  print(f"[*] Finished enumerating {count} domains and found {sub_count} subdomains in total")

