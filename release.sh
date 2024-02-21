rm -rf build
rm -rf dist
rm -rf release
rm -rf venv

python3 -m venv venv
./venv/bin/python3 -m pip install --upgrade pip
./venv/bin/python3 -m pip install -r requirements.txt
./venv/bin/python3 -m pip install pyinstaller

./venv/bin/pyinstaller main.py --clean --onefile

cp ./readme.md ./dist/readme.md
cp ./config.ini ./dist/config.ini
cp -a ./webroot ./dist/webroot
mv dist release
mv ./release/main ./release/pyssdp_server
rm -rf build
rm -rf dist
rm -rf venv
rm -rf *.spec
