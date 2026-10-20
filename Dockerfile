FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
ENV HOST=0.0.0.0 PORT=7860 HUB_BEHIND_PROXY=1
EXPOSE 7860
CMD ["python", "server.py"]
