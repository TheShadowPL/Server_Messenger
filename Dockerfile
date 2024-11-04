# Używamy oficjalnego obrazu Python 3.8
FROM python:3.12.0-alpine

# Ustawiamy katalog roboczy w kontenerze
WORKDIR /app

# Kopiujemy pliki requirements
COPY requirements.txt .

# Instalujemy zależności
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy resztę kodu aplikacji
COPY . .

# Ustawiamy zmienne środowiskowe
ENV FLASK_APP=app
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1

# Otwieramy port 5000 (domyślny dla Flask)
EXPOSE 5001

# Uruchamiamy aplikację
CMD ["flask", "run", "--host=0.0.0.0"]