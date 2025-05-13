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
      // 역방향 변환 (hxxps -> https, [.] -> .)
      return line
        .replace(/hxxps?/gi, 'http')
        .replace(/\[\.\]/g, '.')
        .replace(/\[(\d{1,3})\]\.(\d{1,3})\[(\d{1,3})\]\.(\d{1,3})/g, '$1.$2.$3.$4'); // IP 주소 역방향
    } else {
      // 정방향 변환 (https -> hxxps, . -> [.] )
      return line
        .replace(/https?/gi, 'hxxp')
        .replace(/\./g, '[.]')
        .replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, '$1[.]$2[.]$3[.]$4'); // IP 주소 변환
    }
  }).join('\n');

  outputArea.value = output;
}
