# Faithful-core harness image (shared by v0/v1/v2; behaviour selected by PCB_VER).
FROM python:3.11-slim
RUN pip install --no-cache-dir "pymysql==1.1.1"
WORKDIR /app
COPY harness/ /app/
EXPOSE 8080
CMD ["python", "app.py"]
