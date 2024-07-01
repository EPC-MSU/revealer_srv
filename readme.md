# PySSDP Server

Сервер c поддержкой SSDP на Python.

#### Принцип работы

Скрипт запускает SSDP-сервер, который подключается к мультикастной группе SSDP на всех сетевых адаптерах и прослушивает все входящие SSDP-сообщения. При получении корректного сообщения M-SEARCH, он отвечает по протоколу UPnP, а затем отправляет NOTIFY-пакеты по всем доступным адаптерам, чтобы клиент смог обнаружить устройство, даже если оно находится в другой сети.
Также запускается HTTP-сервер, который при получении запроса возвращает xml-файл с информацией об устройстве. Эту информацию скрипт получает из конфигурационного файла `config.ini`.

## Совестимость

Windows, Linux, macOS. Python 3.6+.

## Конфигурационный файл

В папке с программой/скриптом должен присутствовать конфигурационный файл `config.ini`.

#### Структура конфигурационного файла:

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
presentation_port =

[SERVER]
os =
os_version =
product =
product_version =
password =
mipas_script_path =
interfaces_update_timeout_sec =
```

Для работы программы обязательно должны быть заполнены поля *friendly_name*, *product* и *product_version*. Остальные поля могут отсутствовать или быть пустыми - они будут интерпретированы как пустые строки или заменены значениями по умолчанию.

#### Разъяснения к полям конфигурационного файла

__Для всех полей__: если не сказано иного, то символ `%` допустим в значении поля, однако из-за особенности `ini`-файлов необходимо продублировать символ процента для корректной интерпретации строчки. Например: чтобы задать имя модели `model%1` в конфигурационном файле нужно указать`model_name = model%%1`.

* `friendly_name` - понятное название устройства. Может содержать любые любые латинские буквы, цифры, пробелы, знаки препинания, скобки.
* `manufacturer` - производитель устройства. Может содержать любые латинские буквы, цифры, пробелы, знаки препинания, скобки.
* `manufacturer_url` - ссылка на сайт производителя. Один абсолютный URL. Замечание для обнаружения в сетевых устройствах Windows: Windows будет добавлять `http` к указанной ссылке, если она не сожержит `http` или `https`.
* `model_description` - описание устройства. Может содержать любые латинские буквы, цифры, пробелы, знаки препинания, скобки.
* `model_name` - название модели устройства. Может содержать любые любые латинские буквы, цифры, пробелы, знаки препинания, скобки.
* `model_number` - номер модели устройства. Может содержать любые латинские буквы, цифры, пробелы, знаки препинания, скобки.
* `model_url` - ссылка на модель устройства. Один абсолютный URL. Замечание для обнаружения в сетевых устройствах Windows: Windows будет добавлять `http` к указанной ссылке, если она не сожержит `http` или `https`.
* `serial_number` - серийный номер устройства. Как правило, это число или строка из латинских букв и цифр, но знаки препинания и пробелы также допустимы.
* `presentation_url` - ссылка на основную страницу устройства, которая будет открываться по двойному клику в сетевых устройствах и отображаться в других поисковых программах. Должен быть относительным к URL, по которому возвращается xml-описание устройства. Пример: PySSDP сервер запущен на устройстве с одним сетевым адаптером, у которого IPv4 адрес `192.168.1.1`. Тогда, если не задан порт переадресации `presentation_port` (см. описание использования ниже), то основная страница устройства будет запрошена по ссылке:
```
http://192.168.1.1:5050<presentation_url>
```
А если порт переадресации `presentation_port` задан, то:
```
http://192.168.1.1:<presentation_port><presentation_url>
```

* `presentation_port` - порт переадресации для `presentation_url`. Может содержать только цифры. Используется в случае, если на устройстве уже есть HTTP-сервер на другом порту, который хотелось бы использовать в качестве основного при открытии устройства. Например: есть устройство, у которого на 80 порту уже настроен HTTP-сервер с основной страницей `/main.html`, и вы хотите с помощью PySSDP-сервера настроить обнаружение по SSDP так, чтобы основной страницей остался ваш уже настроенный HTTP-сервер. Тогда в конфигурационном файле нужно указать (остальные поля опущены для простоты, но они тоже должны быть заполнены):
```
presentation_url = /main.html
presentation_port = 80
```
В этом случае PySSDP сервер будет настроен на переадресацию `presentation_url` на сервер на порту 80.
Если же переадресацию делать не требуется, то оставьте поле `presentation_port` пустым. Тогда будет использован дефолтный номер порта 5050 для HTTP-сервера PySSDP сервера и файлы из папки `webroot` для его работы. Вы можете модифицировать `index.html` из этой папки для использования в качестве основной страницы вашего устройства.

* `os` - название операционной системы. Может содержать любые латинские буквы, цифры, знаки препинания. __Не__ должно содержать пробелов.
* `os_version` - версия операционной системы. Может содержать цифры и точки. __Не__ должно содержать пробелов.
* `product` - краткое и емкое название продукта. Может содержать любые латинские буквы, цифры, знаки препинания. __Не__ должно содержать пробелов.
* `product_version` - версия продукта. Может содержать цифры и точки. __Не__ должно содержать пробелов.
* `password` - пароль для смены сетевых настроек по мультикасту. Может содержать любые латинские буквы, цифры и символы, кроме специальных (перенос строки, конец строки, перенос каретки, нулевой символ и т.д.).
* `mipas_script_path` - путь до скрипта (batch или shell в зависимости от системы) для смены сетевых настроек. Скрипт должен принимать в качестве аргументов:
    + __--interface \<interface>__ - имя интерфейса.
    + __--dhcp <0|1>__  - выбор метода установки IPv4 адреса; 0 - использовать статическое задание настроек, 1 - использовать динамический метод получения настроек от DHCP-сервера.
    + __--ipv4 \<address>__ - IPv4 адрес для установки. Будет применен, только если передан параметр `--dhcp 0` (статический метод получения настроек).
    + __--netmask \<address>__ - маска подсети. Будет применена, только если передан параметр `--dhcp 0` (статический метод получения настроек).
    + __--gateway \<address>__ - шлюз по умолчанию. Будет применен, только если передан параметр `--dhcp 0` (статический метод получения настроек).
* `interfaces_update_timeout_sec` - время между проверками текущего списка сетевых интерфейсов системы. Задается в секундах. Не рекомендуется задавать это время равным 0, так как эта проверка может блокировать основную работу сервера. Значение по умолчанию в случае отсутствия этого поля в `config.ini` или в случае его незаполненности будет установлено равным 10 секундам.

## Папка webroot

Это папка содержит в себе файлы для всроенного в PySSDP-сервер HTTP-сервера на порту `5050`. По умолчанию в нем находятся:

* __index.html__ - основная страница устройства 
* __favicon.ico__ - иконка страницы
* __upnp_description.xml__ - xml-файл с описанием UPnP устройства (при отсуствии этого файла сервер не будет обнаруживаться как UPnP устройство, только SSDP)

При необходимости все файлы можно изменить или добавить новые.

Если вы хотите, чтобы какой-то другой файл из этой папки был основным вместо `index.html`, то добавьте его и поменяйте значение поле `presentation_url` с `/index.html` на путь до вашего файла.

## Запуск

### Запуск в Windows (из venv)

* из папки проекта создать виртуальное окружение:
```
python -m venv venv
```

* установить необходимые модули в виртуальное окружение:
```
venv\Scripts\python -m pip install -r requirements.txt
```

* запустить сервер:
```
venv\Scripts\python main.py
```

### Запуск в Linux (из venv)

Может потребоваться установка версии Python с виртуальным окружением:
```
sudo apt-get install python3-venv
```

* из папки проекта создать виртуальное окружение:
```bash
python3 -m venv venv
```

* установить необходимые модули в виртуальное окружение:
```bash
venv/bin/python3 -m pip install -r requirements.txt
```

* запустить сервер:
```bash
venv/bin/python3 main.py
```

### Запуск в macOS (из venv)

* из папки проекта создать виртуальное окружение:
```bash
python3 -m venv venv
```

* установить необходимые модули в виртуальное окружение:
```bash
venv/bin/python3 -m pip install -r requirements.txt
```

* запустить сервер:
```bash
venv/bin/python3 main.py
```

## Автозапуск на Linux

* проверьте, что в `config.ini` находится актуальная информация об устройстве и что все файлы HTTP-сервера в папке `webroot` являются актуальными

* запустите скрипт `install.sh` из папки `scripts` установки сервера в систему и настройки автозапуска (требуются root права для изменения системных сервисов):
```
cd ./scripts
sudo chmod +x install.sh
sudo ./install.sh
```

* для остановки и удаления сервера из системы выполните скрипт `uninstall.sh` из папки `scripts` (также требуются root права):
```
cd ./scripts
sudo chmod +x uninstall.sh
sudo ./uninstall.sh
```

* для просмотра последних логов установленного сервиса можно использовать команду просмотра статуса:
```
sudo systemctl status pyssdp_server.service
```
или чтобы просмотреть все логи:
```
journalctl -u pyssdp_server.service
```

## Примеры использования

#### Настройка переадресации `presentationURL`
    
* Дано: есть устройство с уже настроенным HTTP-сервером на порту `80` и основной страницей `main.html` и хочется использовать именно его для открытия устройства.
* Решение:
    * изменить в конфигурационном файле `config.ini` следующие поля на следующее:
    ```
    presentation_url = /main.html
    presentation_port = 80
    ```
    * Перезапустить PySSDP сервер.

*__Замечание про переадресацию__: изменить можно только порт основной страницы. IP-адрес будет тем же, что и адрес сетевого адаптера. Также обратите внимание, что переадресация на страницы с доменными именами не поддерживается.*

#### Настройка возможности менять настройки с помощью SSDP

* Дано: вы хотите иметь возможность менять настройки вашего устройства без необходимости подключаться к нему напрямую или переводить ваш ПК в другую сеть для подключения к устройству с текущими настройками.
* Решение:
    * доработать скрипт для вашей операционной системы (`netset.sh` или `netset.bat` в папке `scripts`), чтобы переданные аргументы, описанные в разделе "Разъяснения к полям конфигурационного файла", использовались для изменения настроек устройства
    * указать путь до вашего скрипта в конфигурационного файла `config.ini`
    * задать пароль для смены настроек. Поле пароля можно оставить пустым, если требуется.
    * Например, если `netset.sh` находится в папке `scripts` и пароль хочется установить `0000`:
    ```
    password = 0000
    mipas_script_path = scripts/netset.sh
    ```
    * Перезапустить PySSDP сервер.