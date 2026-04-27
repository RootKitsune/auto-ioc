function checkIpList(ipList) {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/;

  for (let ip of ipList) {
    if (!ipv4Regex.test(ip)) {
      alert(`❗유효하지 않은 IP 주소: ${ip}`);
      return false;
    }
  }

  return true
}

// ============== GLOBALS & HELPERS ==============
function populateActionLinks(ip, linkCell) {
    const a = document.createElement("a");
    a.href = `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
    a.innerText = "[VT조회]";
    a.target = "_blank"; 
    a.rel = "noopener noreferrer"; 
    linkCell.appendChild(a);
    
    // 개별 추출 버튼 추가
    const dlBtn = document.createElement("a");
    dlBtn.href = "#";
    dlBtn.innerText = " [📥개별추출]";
    dlBtn.style.color = "var(--primary-color)";
    dlBtn.style.cursor = "pointer";
    dlBtn.style.marginLeft = "8px";
    dlBtn.onclick = (ev) => {
        ev.preventDefault();
        exportSingleRawLog(ip, dlBtn);
    };
    linkCell.appendChild(dlBtn);
}

// nord vpn
function nordIplookup() {
  const ipInput = document.getElementById('ipInput').value.trim();
  const ipListRaw = ipInput.split('\n').map(ip => ip.trim()).filter(ip => ip);
  const ipList = [...new Set(ipListRaw)]; // 중복 제거

  if (ipList.length === 0) return;
  if (ipList.length > 30) {
    alert("❗Nord VPN 조회는 한 번에 최대 30개까지만 허용됩니다.");
    return;
  }
  if (checkIpList(ipList) == false) return;

  alert("과부하 방지를 위해 1초에 한번 검색합니다.");
  const resultTableBody = document.getElementById('resultTable').getElementsByTagName('tbody')[0];
  resultTableBody.innerHTML = '';  // 기존 결과 지우기

  ipList.forEach((ip, index) => {
    setTimeout(() => {
      fetch(`/nord/ip/${ip}`)
        .then(response => response.json())
        .then(data => {
          const country = data.country_code ? getCountryName(data.country_code) : '알 수 없음';
          const country_en = data.country_en_name;
          const country_code = data.country_code;
          const hitCount = window.ipCounts && window.ipCounts[ip] ? window.ipCounts[ip] : '-';
          const row = resultTableBody.insertRow(); 

          row.insertCell(0).innerText = ip;
          row.insertCell(1).innerText = hitCount;
          row.insertCell(2).innerText = country;
          row.insertCell(3).innerText = country_en;
          row.insertCell(4).innerText = country_code;

          populateActionLinks(ip, row.insertCell(5));
        })
        .catch(error => {
          const hitCount = window.ipCounts && window.ipCounts[ip] ? window.ipCounts[ip] : '-';
          const row = resultTableBody.insertRow();
          row.insertCell(0).innerText = ip;
          row.insertCell(1).innerText = hitCount;
          row.insertCell(2).innerText = '조회 실패';
          row.insertCell(3).innerText = '조회 실패';
          row.insertCell(4).innerText = '조회 실패';
          populateActionLinks(ip, row.insertCell(5));
          console.log(error);
        }).finally(() => {
          filterTable(); // 결과가 추가된 후 필터링 즉시 적용
        });
    }, index * 1000);  // 1초마다 하나씩 조회
  });
}

// whois
function whoisIplookup() {
  const ipInput = document.getElementById('ipInput').value.trim();
  const ipListRaw = ipInput.split('\n').map(ip => ip.trim()).filter(ip => ip);
  const ipList = [...new Set(ipListRaw)]; // 중복 제거

  if (ipList.length === 0) return;
  if (ipList.length > 1000) {
    alert("❗KISA Whois 조회는 한 번에 최대 1000개까지만 허용됩니다.");
    return;
  }
  if (checkIpList(ipList) == false) return;

  alert("과부하 방지를 위해 0.2초에 한번 검색합니다.");
  const resultTableBody = document.getElementById('resultTable').getElementsByTagName('tbody')[0];
  resultTableBody.innerHTML = '';  // 기존 결과 지우기

  ipList.forEach((ip, index) => {
    setTimeout(() => {
      fetch(`/whois/ip/${ip}`)
        .then(response => response.json())
        .then(data => {
          const country = data.countryCode ? getCountryName(data.countryCode) : '알 수 없음';
          const country_en = data.country_en_name;
          const country_code = data.countryCode;
          const hitCount = window.ipCounts && window.ipCounts[ip] ? window.ipCounts[ip] : '-';
          const row = resultTableBody.insertRow(); 

          row.insertCell(0).innerText = ip;
          row.insertCell(1).innerText = hitCount;
          row.insertCell(2).innerText = country;
          row.insertCell(3).innerText = country_en;
          row.insertCell(4).innerText = country_code;

          populateActionLinks(ip, row.insertCell(5));
        })
        .catch(error => {
          const hitCount = window.ipCounts && window.ipCounts[ip] ? window.ipCounts[ip] : '-';
          const row = resultTableBody.insertRow();
          row.insertCell(0).innerText = ip;
          row.insertCell(1).innerText = hitCount;
          row.insertCell(2).innerText = '조회 실패';
          row.insertCell(3).innerText = '조회 실패';
          row.insertCell(4).innerText = '조회 실패';
          populateActionLinks(ip, row.insertCell(5));
          console.log(error);
        }).finally(() => {
          filterTable(); // 결과가 추가된 후 필터링 즉시 적용
        });
    }, index * 200);  // 0.2초마다 하나씩 조회
  });
}




// 국가 코드에서 국가명으로 변환
function getCountryName(countryCode) {
  const countries = {
    "AD": "안도라",
    "AE": "아랍에미리트",
    "AF": "아프가니스탄",
    "AG": "앤티가 바부다",
    "AI": "앵귈라",
    "AL": "알바니아",
    "AM": "아르메니아",
    "AO": "앙골라",
    "AR": "아르헨티나",
    "AS": "아메리칸사모아",
    "AT": "오스트리아",
    "AU": "오스트레일리아",
    "AW": "아루바",
    "AZ": "아제르바이잔",
    "BA": "보스니아 헤르체고비나",
    "BB": "바베이도스",
    "BD": "방글라데시",
    "BE": "벨기에",
    "BF": "부르키나파소",
    "BG": "불가리아",
    "BH": "바레인",
    "BI": "부룬디",
    "BJ": "베냉",
    "BM": "버뮤다",
    "BN": "브루나이",
    "BO": "볼리비아",
    "BR": "브라질",
    "BS": "바하마",
    "BT": "부탄",
    "BW": "보츠와나",
    "BY": "벨라루스",
    "BZ": "벨리즈",
    "CA": "캐나다",
    "CD": "콩고민주공화국",
    "CF": "중앙아프리카공화국",
    "CG": "콩고",
    "CH": "스위스",
    "CI": "코트디부아르",
    "CL": "칠레",
    "CM": "카메룬",
    "CN": "중국",
    "CO": "콜롬비아",
    "CR": "코스타리카",
    "CU": "쿠바",
    "CV": "카보베르데",
    "CY": "키프로스",
    "CZ": "체코",
    "DE": "독일",
    "DJ": "지부티",
    "DK": "덴마크",
    "DM": "도미니카 연방",
    "DO": "도미니카 공화국",
    "DZ": "알제리",
    "EC": "에콰도르",
    "EE": "에스토니아",
    "EG": "이집트",
    "ER": "에리트레아",
    "ES": "스페인",
    "ET": "에티오피아",
    "FI": "핀란드",
    "FJ": "피지",
    "FM": "미크로네시아",
    "FR": "프랑스",
    "GA": "가봉",
    "GB": "영국",
    "GD": "그레나다",
    "GE": "조지아",
    "GH": "가나",
    "GM": "감비아",
    "GN": "기니",
    "GQ": "적도 기니",
    "GR": "그리스",
    "GT": "과테말라",
    "GW": "기니비사우",
    "GY": "가이아나",
    "HN": "온두라스",
    "HR": "크로아티아",
    "HT": "아이티",
    "HU": "헝가리",
    "ID": "인도네시아",
    "IE": "아일랜드",
    "IL": "이스라엘",
    "IN": "인도",
    "IQ": "이라크",
    "IR": "이란",
    "IS": "아이슬란드",
    "IT": "이탈리아",
    "JM": "자메이카",
    "JO": "요르단",
    "JP": "일본",
    "KE": "케냐",
    "KG": "키르기스스탄",
    "KH": "캄보디아",
    "KI": "키리바시",
    "KM": "코모로",
    "KN": "세인트키츠 네비스",
    "KP": "북한",
    "KR": "한국",
    "KW": "쿠웨이트",
    "KZ": "카자흐스탄",
    "LA": "라오스",
    "LB": "레바논",
    "LC": "세인트루시아",
    "LI": "리히텐슈타인",
    "LK": "스리랑카",
    "LR": "라이베리아",
    "LS": "레소토",
    "LT": "리투아니아",
    "LU": "룩셈부르크",
    "LV": "라트비아",
    "LY": "리비아",
    "MA": "모로코",
    "MC": "모나코",
    "MD": "몰도바",
    "ME": "몬테네그로",
    "MG": "마다가스카르",
    "MH": "마셜 제도",
    "MK": "북마케도니아",
    "ML": "말리",
    "MM": "미얀마",
    "MN": "몽골",
    "MR": "모리타니",
    "MT": "몰타",
    "MU": "모리셔스",
    "MV": "몰디브",
    "MW": "말라위",
    "MX": "멕시코",
    "MY": "말레이시아",
    "MZ": "모잠비크",
    "NA": "나미비아",
    "NE": "니제르",
    "NG": "나이지리아",
    "NI": "니카라과",
    "NL": "네덜란드",
    "NO": "노르웨이",
    "NP": "네팔",
    "NR": "나우루",
    "NZ": "뉴질랜드",
    "OM": "오만",
    "PA": "파나마",
    "PE": "페루",
    "PG": "파푸아뉴기니",
    "PH": "필리핀",
    "PK": "파키스탄",
    "PL": "폴란드",
    "PT": "포르투갈",
    "PW": "팔라우",
    "PY": "파라과이",
    "QA": "카타르",
    "RO": "루마니아",
    "RS": "세르비아",
    "RU": "러시아",
    "RW": "르완다",
    "SA": "사우디아라비아",
    "SB": "솔로몬 제도",
    "SC": "세이셸",
    "SD": "수단",
    "SE": "스웨덴",
    "SG": "싱가포르",
    "SI": "슬로베니아",
    "SK": "슬로바키아",
    "SL": "시에라리온",
    "SM": "산마리노",
    "SN": "세네갈",
    "SO": "소말리아",
    "SR": "수리남",
    "SS": "남수단",
    "ST": "상투메 프린시페",
    "SV": "엘살바도르",
    "SY": "시리아",
    "SZ": "에스와티니",
    "TD": "차드",
    "TG": "토고",
    "TH": "태국",
    "TJ": "타지키스탄",
    "TL": "동티모르",
    "TM": "투르크메니스탄",
    "TN": "튀니지",
    "TO": "통가",
    "TR": "튀르키예",
    "TT": "트리니다드 토바고",
    "TV": "투발루",
    "TZ": "탄자니아",
    "UA": "우크라이나",
    "UG": "우간다",
    "US": "미국",
    "UY": "우루과이",
    "UZ": "우즈베키스탄",
    "VA": "바티칸",
    "VC": "세인트빈센트 그레나딘",
    "VE": "베네수엘라",
    "VN": "베트남",
    "VU": "바누아투",
    "WS": "사모아",
    "YE": "예멘",
    "ZA": "남아프리카공화국",
    "ZM": "잠비아",
    "ZW": "짐바브웨"
  };
  return countries[countryCode] || countryCode;
}

// ============== NEW FEATURES ==============
window.currentJobId = null;
window.currentFileName = null;

document.addEventListener('DOMContentLoaded', () => {
  const fileInput = document.getElementById('ipFileInput');
  if(fileInput) {
      fileInput.addEventListener('change', async (e) => {
          const file = e.target.files[0];
          if(!file) return;
          const status = document.getElementById('uploadStatus');
          status.innerText = `[PROCESSING] ${file.name}...`;
          status.style.color = "var(--accent-color)";
          
          const formData = new FormData();
          formData.append('file', file);
          const preserveLogs = document.getElementById('preserveLogsToggle').checked;
          formData.append('preserveLogs', preserveLogs);
          
          try {
              const res = await fetch('/upload/extract', {
                  method: 'POST',
                  body: formData
              });
              if(!res.ok) throw new Error('네트워크 응답 오류');
              const data = await res.json();
              if(data.error) throw new Error(data.error);
              
              window.currentJobId = data.job_id || null;
              window.currentFileName = data.filename || null;
              window.ipCounts = data.counts || {};
              
              const existingValue = document.getElementById('ipInput').value.trim();
              const newLines = existingValue ? existingValue + '\n' + data.ips.join('\n') : data.ips.join('\n');
              document.getElementById('ipInput').value = newLines;
              
              status.innerText = `[SUCCESS] 원본 파일에서 ${data.ips.length}개의 고유 IP를 추출했습니다.`;
              status.style.color = "var(--primary-color)";
              fileInput.value = ""; // 초기화
          } catch(err) {
              status.innerText = `[ERROR] IP 추출에 실패했습니다.`;
              status.style.color = "var(--secondary-color)";
              console.error(err);
          }
      });
  }

  // 필터 초기화
  const fk = document.getElementById('filterKr');
  const fnk = document.getElementById('filterNonKr');
  if(fk) fk.addEventListener('change', filterTable);
  if(fnk) fnk.addEventListener('change', filterTable);
});

function filterTable() {
  const showKr = document.getElementById('filterKr').checked;
  const showNonKr = document.getElementById('filterNonKr').checked;
  const rows = document.querySelectorAll('#resultTable tbody tr');
  
  rows.forEach(row => {
      const nationCode = row.cells[4].innerText.trim().toUpperCase(); 
      let isKr = (nationCode === 'KR');
      if (nationCode === '조회 실패' || nationCode === '알 수 없음' || nationCode === 'ERR' || nationCode === 'FAIL' || !nationCode) {
         isKr = false;
      }
      
      if (isKr && !showKr) {
          row.style.display = 'none';
      } else if (!isKr && !showNonKr) {
          row.style.display = 'none';
      } else {
          row.style.display = '';
      }
  });
}

function exportResults(type) {
  const rows = Array.from(document.querySelectorAll('#resultTable tbody tr')).filter(row => row.style.display !== 'none');
  if (rows.length === 0) {
      alert("출력할 데이터가 없습니다.");
      return;
  }
  
  let content = "";
  if (type === 'csv') {
      content = "IP_ADDR,HIT_COUNT,NATION_KR,NATION_EN,CODE\n";
      rows.forEach(row => {
          const ip = row.cells[0].innerText;
          const hitCount = row.cells[1].innerText;
          const nationKr = row.cells[2].innerText;
          const nationEn = row.cells[3].innerText;
          const code = row.cells[4].innerText;
          content += `${ip},${hitCount},${nationKr},${nationEn},${code}\n`;
      });
      downloadFile(content, 'ip_lookup_result.csv', 'text/csv');
  } else if (type === 'log') {
      rows.forEach(row => {
          const ip = row.cells[0].innerText;
          const hitCount = row.cells[1].innerText;
          const nationKr = row.cells[2].innerText;
          const code = row.cells[4].innerText;
          const timestamp = new Date().toISOString();
          content += `[${timestamp}] IP: ${ip} | HIT_COUNT: ${hitCount} | NATION: ${nationKr} (${code})\n`;
      });
      downloadFile(content, 'ip_lookup_result.log', 'text/plain');
  }
}

function downloadFile(content, filename, contentType) {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportRawLogs() {
  if (!window.currentJobId) {
      alert("서버에 보존된 원본 로그 파일이 없습니다!\n(새로고침 했거나, 파일 업로드 시 '[기능] 원문 보존형 로직 활성화' 토글을 켜지 않았습니다.)");
      return;
  }
  
  const rows = Array.from(document.querySelectorAll('#resultTable tbody tr')).filter(row => row.style.display !== 'none');
  if (rows.length === 0) {
      alert("추출할 타겟 IP(결과 테이블에 보이는 목록)가 없습니다.");
      return;
  }
  
  const targetIps = rows.map(row => row.cells[0].innerText);
  const btn = document.querySelector('.raw-btn');
  const orgText = btn.innerText;
  btn.innerText = "⏳ EXTRACTING...";
  
  fetch('/export/raw', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
          job_id: window.currentJobId,
          target_ips: targetIps,
          filename: window.currentFileName
      })
  })
  .then(async res => {
      const contentType = res.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
          const errData = await res.json();
          throw new Error(errData.error || "Server Error");
      }
      if (!res.ok) {
          throw new Error("서버 오류가 발생했습니다.");
      }
      return res.blob();
  })
  .then(blob => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      let safeFilename = window.currentFileName ? window.currentFileName.replace(/[^a-zA-Z0-9.\-_]/g, '_') : 'logs';
      a.download = `raw_logs_by_ip_${safeFilename}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
  })
  .catch(err => {
      console.error(err);
      alert(err.message || "원문 로그를 추출하는 도중 서버 오류가 발생했습니다.");
  })
  .finally(() => {
      btn.innerText = orgText;
  });
}

function exportSingleRawLog(targetIp, elm) {
  if (!window.currentJobId) {
      alert("서버에 보존된 원본 로그 파일이 없습니다!\n(새로고침 했거나, 파일 업로드 시 '[기능] 원문 보존형 로직 활성화' 토글을 켜지 않았습니다.)");
      return;
  }
  
  const orgText = elm.innerText;
  elm.innerText = " [⏳처리중]";
  
  fetch('/export/raw', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
          job_id: window.currentJobId,
          target_ips: [targetIp],
          filename: window.currentFileName
      })
  })
  .then(async res => {
      const contentType = res.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
          const errData = await res.json();
          throw new Error(errData.error || "Server Error");
      }
      if (!res.ok) {
          throw new Error("서버 오류가 발생했습니다.");
      }
      return res.blob();
  })
  .then(blob => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      let safeFilename = window.currentFileName ? window.currentFileName.replace(/[^a-zA-Z0-9.\-_]/g, '_') : 'logs';
      a.download = `raw_log_${targetIp.replace(/[^0-9.]/g, '_')}_${safeFilename}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
  })
  .catch(err => {
      console.error(err);
      alert(err.message || "원문 로그 추출 도중 서버 오류가 발생했습니다.");
  })
  .finally(() => {
      elm.innerText = orgText;
  });
}
