FROM python:3.7

RUN pip install fastapi uvicorn aiofiles python-multipart pycryptodome

#COPY ./app /app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
