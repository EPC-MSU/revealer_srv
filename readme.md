# PySSDP Server

Сервер c поддержкой SSDP на python.

#### Принцип работы:

Скрипт запускает SSDP-сервер, который подключается к мультикастной группе SSDP на всех адаптерах и прослушивает все входящие SSDP-сообщения. При получении правильного M-SEARCH, он отвечает по протоколу UPnP, а затем отправляет NOTIFY-пакеты по всем доступным адаптерам (чтобы клиент смог обнаружить устройство, даже если оно находится в другой сети).
Также запускается HTTP-сервер, который при получении запроса возвращает xml-файл с информацией об устройстве. Эту информацию скрипт получает из конфигурационного файла `config.ini`. 

## Конфигурационный файл

В папке с программой/скриптом должен присутствовать конфигурационный файл `config.ini`. \
Структура конфигурационного файла:

```ini
[MAIN]
friendly_name =
manufacturer =
manufacturer_url =
model_description =
model_name =
model_number =
model_url =
serial_number =
presentation_url =

[SERVER]
os =
os_version =
product =
product_version =
```

Для работы программы обязательно должны быть заполнены поля *friendly_name*, *product* и *product_version*. Остальные поля могут отсутствовать или быть пустыми - они будут интерпретированы как пустые строки.

## Папка webroot

Это папка содержит в себе файлы для поднимаемого HTTP-сервера. По умолчанию в нем находятся:

* index.html - основная страница устройства 
* favicon.ico - иконка страницы
* Basic_info.xml - xml-файл с описанием UPnP устройства (при отсуствии этого файла сервер не будет обнаруживаться как UPnP устройство, только SSDP)

При необходимости все файлы можно изменить или добавить новые, однако эти три файла должны присутсвовать для корректного работы сервера. 

## Автозапуск на Linux

* проверьте, что в config.ini и находится актуальная информация об устройстве и что все файлы веб-сервера в папке webroot являются актуальными

* запустить скрипт установки сервера в систему и настройки автозапуска (требуются root права для изменения системных сервисов):

```
sudo chmod +x install.sh
sudo ./install.sh
```

* для остановки и удаления сервера из системы выполните скрипт (также требуются root права):

```
sudo chmod +x uninstall.sh
sudo ./uninstall.sh
```

* для просмотра последних логов установленного сервиса можно использовать команду просмотра статуса:

```
sudo systemctl status pyssdp_server.service
```

## Выпуск релиза

### Выпуск релиза в Windows

* Для выпуска релиза в Windows нужно выполнить скрипт `release.bat`:

```
release.bat
```

* Для ветки, из которой выпускался релиз, добавить метку (tag) вида v1.2.3 на коммит, из которого будет собираться релиз.
* Увеличить номер версии в файле version.py и зафиксировать это коммитом с комментарием Version increment.

### Выпуск релиза в Linux

* Установите версию python3 с поддержкой виртуальных окружений, a также binutils для работы pyinstaller:
  
  ```bash
  sudo apt-get install python3-venv binutils
  ```
* Для выпуска релиза в Linux нужно выполнить скрипт `release.sh`:
  
  ```bash
  bash release.sh
  ```
* Для ветки, из которой выпускался релиз, добавить метку (tag) вида v1.2.3 на коммит, из которого будет собираться релиз.
* Увеличить номер версии в файле version.py и зафиксировать это коммитом с комментарием Version increment.

## Запуск скрипта на python

Установить зависимости (см. requirements.txt) в виртуальное окружение, перейти в папку с файлом main.py и запустить скрипт:

### Запуск в Windows (из venv)

```bash
venv\Scripts\python main.py
```

### Запуск в Linux (из venv)

```bash
venv/bin/python3 main.py
```