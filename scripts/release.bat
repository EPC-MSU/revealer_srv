cd ..

if exist build rd /S /Q build
if exist dist rd /S /Q dist
if exist release rd /S /Q release
if exist venv rd /S /Q venv

python -m venv venv
venv\Scripts\python -m pip install --upgrade pip
venv\Scripts\python -m pip install -r requirements.txt
venv\Scripts\python -m pip install pyinstaller
venv\Scripts\pyinstaller main.py --clean --onefile

copy README.md dist
copy config.ini dist
mkdir dist\webroot
copy webroot dist\webroot
rename dist release
cd release
rename main.exe pyssdp_server.exe

cd ..
if exist build rd /S /Q build
if exist dist rd /S /Q dist
if exist venv rd /S /Q venv
if exist *.spec del *.spec

cd scripts

pause