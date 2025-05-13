FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
COPY source/ /app/

# 패키지 설치
RUN pip install --no-cache-dir -r requirements.txt

# 컨테이너에서 열 포트 지정 (Flask 기본 포트)
EXPOSE 80

# Flask 실행 명령
CMD ["python", "app.py"]
