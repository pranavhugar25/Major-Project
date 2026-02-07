@echo off
REM PQC Password Manager Setup Script for Windows

echo =========================================
echo PQC Password Manager Setup
echo =========================================
echo.

echo Setting up Backend...
cd backend

REM Create virtual environment
python -m venv venv
echo [✓] Virtual environment created

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
pip install -r requirements.txt
echo [✓] Backend dependencies installed

cd ..

echo.
echo Setting up Frontend...
cd frontend

REM Install dependencies
call npm install
echo [✓] Frontend dependencies installed

cd ..

echo.
echo =========================================
echo Setup Complete!
echo =========================================
echo.
echo To start the application:
echo.
echo 1. Start Backend (Terminal 1):
echo    cd backend
echo    venv\Scripts\activate
echo    python app.py
echo.
echo 2. Start Frontend (Terminal 2):
echo    cd frontend
echo    npm start
echo.
echo The application will be available at:
echo   Frontend: http://localhost:3000
echo   Backend:  http://localhost:5000
echo.
echo =========================================

pause
