from flask import Flask, render_template
import requests as req
import re
import pycountry


import ipaddress

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


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)
