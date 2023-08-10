cd ..
rm -rf build
rm -rf dist
rm -rf release
rm -rf venv

python3 -m venv venv
./venv/bin/python3 -m pip install --upgrade pip
./venv/bin/python3 -m pip install -r requirements.txt
./venv/bin/python3 -m pip install pyinstaller

./venv/bin/pyinstaller main.py --clean --onefile

cp ./README.md ./dist/readme.md
cp ./configuration.ini ./dist/configuration.ini
mv dist release
mv ./release/main ./release/revealer_srv
rm -rf build
rm -rf dist
rm -rf venv
rm -rf *.spec