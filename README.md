Setup & Running

Clone the repository (if not already):

git clone https://github.com/Shree21941/Malicious-File-Detection.git
cd Malicious-File-Detection


Create a virtual environment:

python -m venv venv


Activate the virtual environment:

# Windows PowerShell
.\venv\Scripts\Activate.ps1

# Windows CMD
.\venv\Scripts\activate.bat

# Linux / macOS
source venv/bin/activate


Install dependencies from requirements.txt:

pip install --upgrade pip
pip install -r requirements.txt


Run the FastAPI API:

uvicorn malware_api:app --host 0.0.0.0 --port 8000 --reload


malware_api → your Python script file (e.g., malware_api.py)

app → FastAPI object inside the script

Test the API:

Swagger docs: http://localhost:8000/docs

Health check: http://localhost:8000/api/health
