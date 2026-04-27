const inputArea = document.getElementById('inputArea');
const outputArea = document.getElementById('outputArea');
const reverseCheck = document.getElementById('reverseCheck');

inputArea.addEventListener('input', convertText);
reverseCheck.addEventListener('change', convertText);

function convertText() {
  const input = inputArea.value;
  const reverse = reverseCheck.checked;

  let output = input.split('\n').map(line => {
    if (reverse) {
      // 역방향 변환 (hxxps -> https, hxxp -> http, [.] -> .)
      // [.] 만 .으로 치환하면 IP, 도메인 관계없이 모든 마스킹이 원래대로 전부 복구됨 (IP 정규식 중복 제거)
      return line
        .replace(/hxxps/gi, 'https')
        .replace(/hxxp/gi, 'http')
        .replace(/\[\.\]/g, '.');
    } else {
      // 정방향 변환 (Masking - Defanging)
      let result = line
        .replace(/https/gi, 'hxxps')
        .replace(/http/gi, 'hxxp');

      // 1. IP 주소: D클래스(마지막 옥텟)의 마지막 .만 [.]으로 변환
      // 매칭 예: 192.168.0.1 -> 192.168.0[.]1
      result = result.replace(/(\b\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3}\b)/g, '$1[.]$2');

      // 2. 도메인 (URL/URI): 뒤쪽의 영문 확장자 앞 마지막 .만 [.]으로 변환
      // 매칭 예: example.com -> example[.]com, a.b.co.kr -> a.b.co[.]kr
      result = result.replace(/\.([a-zA-Z]{2,6}(?![-0-9a-zA-Z])(?:\:[0-9]+)?(?:\/|$|\?))/g, '[.]$1');

      return result;
    }
  }).join('\n');


  outputArea.value = output;
}
