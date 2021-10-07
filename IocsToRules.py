import re

iocs_file = r"D:\Test\files\iocs.txt"

def check_iocs_type(iocs):
    if re.match("^#", iocs):
        return "none"
    elif re.match("\d+\.\d+\.\d+\.\d+", iocs):
        return "ip"
    elif re.match("^(?=.{1,253}\.?$)(?:(?!-|[^.]+_)[A-Za-z0-9-_]{1,63}(?<!-)(?:\.|$)){2,}$", iocs):
        return "domain"


def get_query(num_iocs, fields_template):
    domain_query = ""
    ip_query = ""
    url_query = ""
    hash_query = ""

    with open(iocs_file) as f:
        iocs_lines = f.readlines()

    for i in range(len(iocs_lines)):
        iocs_lines[i] = str.strip(iocs_lines[i])

    for lines in range(len(iocs_lines)):
        if check_iocs_type(f"{iocs_lines[lines]}") == "domain":
            domain_query += iocs_lines[lines] + " or "
        if check_iocs_type(f"{iocs_lines[lines]}") == "ip":
            ip_query += iocs_lines[lines] + " or "
        if check_iocs_type(f"{iocs_lines[lines]}") == "url":
            url_query += iocs_lines[lines] + " or "
        if check_iocs_type(f"{iocs_lines[lines]}") == "hash":
            hash_query += iocs_lines[lines] + " or "

    if len(domain_query) != 0:
        domain_query = domain_query[:-4]
        print(f"{fields_template['domain']}: ({domain_query})")
    if len(ip_query) != 0:
        ip_query = ip_query[:-4]
        print(f"{fields_template['destination_ip']}: ({ip_query})")
    if len(url_query) != 0:
        url_query = url_query[:-4]
        print(f"{fields_template['url']}: ({url_query})")
    if len(hash_query) != 0:
        hash_query = hash_query[:-4]
        print(f"{fields_template['hashes']}: ({hash_query})")



def main():
    num_iocs = int(input())
    fields_template = dict()
    default_fields_template = {
        "source_ip": "flow.src_addr",
        "destination_ip": "flow.dst_addr",
        "domain": "dns.question.name",
        "url": "url.origin",
        "hashes": "hashes"
    }
    if True:
        get_query(num_iocs, default_fields_template)
    else:
        get_query(num_iocs, fields_template)



if __name__ == '__main__':
    main()
