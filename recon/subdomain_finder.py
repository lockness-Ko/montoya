import requests
import dataclasses
import argparse
import os
import sys

from bs4 import BeautifulSoup

""" Types """

@dataclasses.dataclass
class Err(BaseException):
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

""" URL helpers """

def extract_subdomain(url: str):
  return url.split("://")[-1].split("/")[0].split("@")[-1].split(":")[0]

""" Services """

def check_alienvault(domain: str):
  response = get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", [200, 400])
  if response.status_code == 400:
    return []
  subdomains = unique(extract_key("hostname", response.json()["passive_dns"]))
  return subdomains

def check_certspotter(domain: str):
  response = get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", [200, 403])
  if response.status_code == 403:
    return []
  subdomains = unique(flat_map(extract_key("dns_names", response.json())))
  return subdomains

def check_crtsh(domain: str):
  response = get(f"https://crt.sh/?q=%.{domain}&output=json")
  subdomains = unique(extract_key("name_value", response.json()))
  return subdomains

def check_hackertarget(domain: str):
  response = get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
  if response.text == "error invalid host":
    return []
  lines = response.text.split("\n")
  if "" in lines:
    lines.remove("")
  subdomains = list(map(lambda x: x.split(",")[0], lines))
  return subdomains

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
  return unique(subdomains)

def check_threatminer(domain: str):
  response = get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", [200, 404])
  if response == 404:
    return []
  return response.json()["results"]

def check_urlscan(domain: str):
  response = get(f"https://urlscan.io/api/v1/search?q={domain}")
  urls = extract_key("url", extract_key("page", response.json()["results"]))
  urls = list(filter(lambda x: domain in x, urls))
  subdomains = unique(map(extract_subdomain, urls))
  if domain in subdomains:
    subdomains.remove(domain)
  return subdomains

def check_webarchive(domain: str):
  response = get(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey")
  urls = response.text.split("\n")
  subdomains = unique(map(extract_subdomain, urls))
  subdomains = list(filter(lambda x: domain in x, subdomains))
  if domain in subdomains:
    subdomains.remove(domain)
  if "" in subdomains:
    subdomains.remove("")
  return subdomains

services = [
  ("otx.alienvault.com", check_alienvault),
  ("api.certspotter.com", check_certspotter),
  ("crt.sh", check_crtsh),
  ("api.hackertarget.com", check_hackertarget),
  ("rapiddns.io", check_rapiddns),
  ("api.threatminer.org", check_threatminer),
  ("urlscan.io", check_urlscan),
  ("web.archive.org", check_webarchive)
]

""" Main """

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Enumerate subdomains of a domain.")
  parser.add_argument("domains", type=str, nargs="+", help="the domain to enumerate subdomains of")
  parser.add_argument("--include-domain", action="store_true", help="include the original domain in the list of subdomains")
  parser.add_argument("-o", "--output-dir", type=str, help="directory to save subdomain lists to")
  args = parser.parse_args()

  domains = args.domains
  include_domain = args.include_domain
  output_dir = args.output_dir

  if output_dir != None:
    if os.path.isdir(output_dir):
      if len(list(filter(lambda x: not x.startswith("."), os.listdir(output_dir)))) != 0:
        sys.exit("error: Output directory already exists and is not empty.")
    else:
      os.mkdir(output_dir)

  sub_count = 0
  for domain in domains:
    print(f"[*] Searching for subdomains of '{domain}'")
    subdomains = set()
    if include_domain:
      subdomains.add(domain)

    for (name, service) in services:
      try:
        print(f"  [*] Searching '{name}'")
        count_before = len(subdomains)
        subdomains.update(service(domain))
        count_after = len(subdomains)
        count = count_after - count_before
        print(f"  [*] Found {count} new subdomains")
      except KeyboardInterrupt as e:
        exit(1)
      except:
        print(f"  [-] Failed to search '{name}'")

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
