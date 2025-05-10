from androguard.core.bytecodes.apk import APK
import re
import requests
import pickle
import json
import os
from django.conf import settings
API_KEY = 'f6bc2dfd7534331fd8f77c2d460a97d54aa65783fa0ca3b164a6a118621c9f09'

headers = {
    "accept": "application/json",
    "x-apikey": API_KEY,
    "content-type": "application/x-www-form-urlencoded"
}
model_file_path = os.path.join(settings.BASE_DIR, 'secureapp', 'models', 'whiteurls.pkl')
with open(model_file_path, 'rb') as f:
    whiteurls = pickle.load(f)
from urllib.parse import urlparse


def extract_urls_from_apk(apk_path):

    urls = set()
    try:
        apk = APK(apk_path)
        for dex in apk.get_all_dex():
            matches = re.findall(b'(https?://[^\s\'"<>]+)', dex)
            for match in matches:
                try:
                    cleaned_urls = [url.strip() for url in re.split(r'(?=https?://)', match.decode('utf-8', errors='ignore')) if url.strip()]
                except UnicodeDecodeError as e:
                    print(f"Error decoding URL: {e}")
                    continue
                urls.update(cleaned_urls)
    except Exception as e:
        print(f"Error extracting URLs from APK: {e}")
    return list(urls)


def scan_and_analyze_url(test_url):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": test_url}

    response = requests.post(scan_url, data=payload, headers=headers)
    if response.status_code == 200:
        response_data = json.loads(response.text)
        url_id = response_data['data']['id'].split('-')[1]
        report_url = "https://www.virustotal.com/api/v3/urls/" + url_id

        response = requests.get(report_url, headers=headers)
        if response.status_code == 200:
            report_data = json.loads(response.text)
            return report_data
        else:
            print(f"Error getting URL report for {test_url}: {response.status_code}")
            return None
    else:
        print(f"Error submitting URL for scan: {response.status_code}")
        return None


def analyze_urls_in_apk(apk_path):
    extracted_urls = extract_urls_from_apk(apk_path)
    blackurls = set()
    for url in extracted_urls:
        try:
            parsed_url = urlparse(url)
            scheme = parsed_url.scheme
            netloc = parsed_url.netloc
            extracted_part = f"{scheme}://{netloc}"
            blackurls.add((url, netloc, extracted_part))
        except ValueError as e:
            print("解析失败：", e)
    filtered_urls = [(url, netloc, part) for url, netloc, part in blackurls if part not in whiteurls]

    analysis_stats = []
    for url, netloc, part in filtered_urls:
        result = scan_and_analyze_url(url)
        if result:
            analysis_stat = result['data']['attributes']['last_analysis_stats']
            analysis_stats.append((url, netloc, analysis_stat))
    weights = {
        'malicious': 100,
        'suspicious': 5,
        'undetected': 0.1,
        'harmless': 0,
        'timeout': 0
    }
    key_sites = []
    for url, netloc, data in analysis_stats:
        weighted_sum = sum(data[key] * weights[key] for key in data)
        normalized_data = {key: (data[key] * weights[key]) / sum(data.values()) for key in data}
        normalized_weight = sum(normalized_data.values())
        key_sites.append({
            'url': url,
            'domain': netloc,
            'danger_level': weighted_sum,
            'normalized_danger_level': normalized_weight,
        })
    return key_sites
