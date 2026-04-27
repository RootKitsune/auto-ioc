from flask import Flask, render_template, request, jsonify, send_file
import requests as req
import re
import pycountry

import ipaddress
import zipfile
import io
import concurrent.futures
import os
import uuid
import collections

TEMP_DIR = os.path.join(os.path.dirname(__file__), '.temp_logs')
os.makedirs(TEMP_DIR, exist_ok=True)


# CIDR 대역 리스트
IP_BLACKLIST_CIDRS = [
    "127.0.0.0/8",       # 루프백
    "0.0.0.0/8",         # 예약됨
    "10.0.0.0/8",        # 프라이빗
    "172.16.0.0/12",     # 프라이빗
    "192.168.0.0/16",    # 프라이빗
    "169.254.0.0/16",    # 링크 로컬
    "224.0.0.0/4",       # 멀티캐스트
    "240.0.0.0/4",       # 미래 예약
    "255.255.255.255/32" # 브로드캐스트
]

# 블랙리스트 네트워크 객체 생성
BLACKLISTED_NETWORKS = [ipaddress.ip_network(cidr) for cidr in IP_BLACKLIST_CIDRS]

def is_blacklisted_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in BLACKLISTED_NETWORKS)
    except ValueError:
        return True  # 잘못된 IP (e.g. 도메인명)도 차단 대상
    

def verify_ip_addr(ip):
    ipv4_regex = re.compile(
        r'^('
        r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}'
        r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$'
    )
    if not ipv4_regex.match(ip):
        return "value error"
    if is_blacklisted_ip(ip):
        return "blackList"
    return True


app = Flask(__name__)

def get_country_name(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)  # 2자리 국가 코드로 조회
        if country:
            return country.name
        else:
            return "알 수 없음"
    except KeyError:
        return "알 수 없음"

# main
@app.route('/')
def home():
    return render_template('app.html')


# nordvpn_ip_ajax
@app.route('/nord/ip/<ip_addr>')
def get_country_name_by_nord(ip_addr):
    # Chrome User-Agent 값 설정 (브라우저처럼 보이도록)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    verified = verify_ip_addr(ip_addr)

    if verified == "value error":
        return "정상 IP가 아닙니다."
    elif verified == "blackList":
        return "블랙리스트 IP 탐지!"
    

    # 서버에 요청을 보낼 때 headers에 User-Agent 추가
    res = req.get(f"https://web-api.nordvpn.com/v1/ips/lookup/{ip_addr}", headers=headers)


    data = res.json()
    country_en_name = {"country_en_name" : get_country_name(data["country_code"])}

    # 혹시 틀릴수도 있으니깐 영문 명 추가
    data.update(country_en_name)

    return data

@app.route('/whois/ip/<ip_addr>')
def get_country_name_by_whois(ip_addr):
    # Chrome User-Agent 값 설정 (브라우저처럼 보이도록)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    verified = verify_ip_addr(ip_addr)

    if verified == "value error":
        return "정상 IP가 아닙니다."
    elif verified == "blackList":
        return "블랙리스트 IP 탐지!"
    
    # key (git ignored)
    # kisa whois api 이용 키, 2025.05.* 갱신
    with open('whois.txt', 'r') as f:
        try:
            key = f.readline().strip()
        except:
            print("[!] 크리덴셜 파일 어디다 팔아먹음")

    params = {
        "serviceKey": key,
        "answer": "JSON",
        "query": ip_addr
    }

    # 서버에 요청을 보낼 때 headers에 User-Agent 추가
    res = req.get(f"http://apis.data.go.kr/B551505/whois/ip_address", headers=headers, params=params)

    try:
        data = res.json()
        res_status = data.get('response', {}).get('result', {}).get('result_msg', '')
        if res_status != "정상 응답 입니다.":
            return jsonify({"countryCode": "FAIL", "country_en_name": f"API 상태: {res_status}"})
        
        whois_data = data['response']['whois']
        country_code = whois_data.get('countryCode', '알 수 없음')
        whois_data["country_en_name"] = get_country_name(country_code)
        
        return jsonify(whois_data)
    except Exception as e:
        # KISA API가 인증키 오류 시 (500/400) XML을 반환하기 때문에 JSON 파싱 에러 발생
        return jsonify({"countryCode": "ERR", "country_en_name": "KISA JSON 오류 (인증키 만료/한도 초과/XML 반환)"})



def extract_ips_from_text(text):
    ipv4_regex = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b'
    )
    return ipv4_regex.findall(text)

def process_file_bytes(file_bytes):
    try:
        text = file_bytes.decode('utf-8', errors='ignore')
        return extract_ips_from_text(text)
    except Exception:
        return []

@app.route('/upload/extract', methods=['POST'])
def upload_extract():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    preserve_logs = request.form.get('preserveLogs') == 'true'
    job_id = str(uuid.uuid4()) if preserve_logs else None
    
    file_bytes = file.read()
    ip_counter = collections.Counter()
    
    if preserve_logs:
        file_path = os.path.join(TEMP_DIR, f"{job_id}_{file.filename}")
        with open(file_path, 'wb') as f:
            f.write(file_bytes)
    
    if file.filename.lower().endswith('.zip'):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    for name in z.namelist():
                        if not name.endswith('/'):
                            futures.append(executor.submit(process_file_bytes, z.read(name)))
                    for future in concurrent.futures.as_completed(futures):
                        ip_counter.update(future.result())
        except Exception as e:
            return jsonify({"error": "ZIP read error", "details": str(e)}), 500
    else:
        ip_counter.update(process_file_bytes(file_bytes))
    
    valid_ips = []
    ip_count_map = {}
    for ip, count in ip_counter.items():
        if verify_ip_addr(ip) == True:
            valid_ips.append(ip)
            ip_count_map[ip] = count
            
    return jsonify({"ips": valid_ips, "counts": ip_count_map, "job_id": job_id, "filename": file.filename})

@app.route('/export/raw', methods=['POST'])
def export_raw():
    data = request.json
    job_id = data.get('job_id')
    target_ips = data.get('target_ips', [])
    filename = data.get('filename', '')
    
    if not job_id or not target_ips:
        return jsonify({"error": "Missing job_id or target_ips"}), 400
        
    file_path = os.path.join(TEMP_DIR, f"{job_id}_{filename}")
    if not os.path.exists(file_path):
        return jsonify({"error": "Original file not found. Make sure you enabled toggle during upload."}), 404
        
    ip_patterns = {ip: re.compile(r'\b' + re.escape(ip) + r'\b') for ip in target_ips}
    matched_lines_by_ip = {ip: [] for ip in target_ips}
    
    def process_file_stream(f_stream, fname=""):
        if fname:
            try:
                fname = fname.encode('cp437').decode('euc-kr') # MS 윈도우/맥 한글 깨짐 대응
            except Exception:
                try:
                    fname = fname.encode('cp437').decode('utf-8')
                except Exception:
                    pass
        prefix = f"{fname}," if fname else ""
        for line in f_stream:
            line_str = line.rstrip()
            for ip, regex in ip_patterns.items():
                if regex.search(line_str):
                    matched_lines_by_ip[ip].append(f"{prefix}{line_str}")

    if filename.lower().endswith('.zip'):
        with zipfile.ZipFile(file_path, 'r') as z:
            for name in z.namelist():
                if not name.endswith('/'):
                    try:
                        with z.open(name) as f:
                            text_stream = io.TextIOWrapper(f, encoding='utf-8', errors='ignore')
                            process_file_stream(text_stream, name)
                    except:
                        pass
    else:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            process_file_stream(f)
            
    has_any_match = any(len(lines) > 0 for lines in matched_lines_by_ip.values())
    if not has_any_match:
        return jsonify({"error": "조건에 매칭되는 원문 행이 없습니다."}), 404
        
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Create a text file for each IP
        for ip, lines in matched_lines_by_ip.items():
            if lines: 
                safe_ip = ip.replace('/', '_').replace(':', '_')
                file_content = "\n".join(lines).encode('utf-8')
                zf.writestr(f"{safe_ip}.txt", file_content)
                
    memory_file.seek(0)
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"raw_logs_{filename}.zip"
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)
