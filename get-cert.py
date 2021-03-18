import pandas
import requests
from bs4 import BeautifulSoup
import re

def getContent(cnum, type):
    headers = {
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.67 Safari/537.36 Edg/87.0.664.47",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://www.google.com/",
        "Accept-Language": "en-GB,en;q=0.9",
    }
    params = ()
    if type == 'VulnerabilityNote':
        params = (
            ("pageid", "PUBVLNOTES01"),
            ("VLCODE", cnum),
        )
    elif type == 'Advisory':
        params = (
            ("pageid", "PUBVLNOTES02"),
            ("VLCODE", cnum),
        )

    return requests.get(
        "https://www.cert-in.org.in/s2cMainServlet", headers=headers, params=params
    ).content


def main():
    df_cve = pandas.DataFrame(columns=['CVIN', 'CVE'])
    df_civn = pandas.read_excel(r'C:\Users\A1YTVI9H\Downloads\a.xlsx', sheet_name=1)
    print(df_civn, end='\n\n')
    for cnum in df_civn["CIVN No"].tolist():
        print(cnum)
        if str(cnum).startswith('CIVN'):
            content = getContent(cnum, 'VulnerabilityNote')
            soup = BeautifulSoup(content, 'html.parser')
            CVEList = soup.body.findAll(text=re.compile('^CVE-[0-9]+-[0-9]+'))
            CVEStr = '\n'.join(CVEList)
            df_cve = df_cve.append({'CVIN': cnum, 'CVE': CVEStr}, ignore_index=True)
        elif str(cnum).startswith('CIAD'):
            content = getContent(cnum, 'Advisory')
            soup = BeautifulSoup(content, 'html.parser')
            CVEList = soup.body.findAll(text=re.compile('^CVE-[0-9]+-[0-9]+'))
            CVEStr = '\n'.join(CVEList)
            # import pdb; pdb.set_trace()
            df_cve = df_cve.append({'CVIN': cnum, 'CVE': CVEStr}, ignore_index=True)
    df_cve.to_excel('CVE.xlsx')
    # import pdb; pdb.set_trace()


main()