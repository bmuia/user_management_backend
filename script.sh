#!/bin/bash

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Running makemigrations..."
python manage.py makemigrations

echo "Running migrate..."

python manage.py migrate
echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Starting server with Gunicorn..."
gunicorn user_management_backend.wsgi:application --workers=2 --bind 0.0.0.0:$PORT


