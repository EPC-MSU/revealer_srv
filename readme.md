# revealer_srv

Сервер c поддержкой SSDP на python. Сервер получает M-SEARCH и отвечает на них по протоколу UPnP,

## Конфигурационный файл

В папке с программой/скриптом должен присутствовать конфигурационный файл *configuration.ini*. \
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

## Автозапуск на Linux

Чтобы настроить автозапуск с помощью systemd, нужно создать сервис revealer, который будет запускаться после подключения устройства к сети.

1. Поместить файл *revealer.service* в папку /etc/systemd/system. \
Bash-скрипт, создающий файл (разумеется, адрес скрипта main.py должен быть правильный):
```bash
cd /etc/systemd/system
echo -e "[Unit]\nDescription=Revealer\nAfter=network-online.target\n\n[Service]\nExecStart=/usr/bin/python3 /home/eyepoint/Develop/server/main.py\n\n[Install]\nWantedBy=multi-user.target" > revealer.service
```


2. Затем дать команду, что этот сервис должен быть включен в автозапуск:

```bash
sudo systemctl enable revealer
sudo systemctl start revealer
```

Если после перезапуска не запустилось, можно посмотреть, что там с программой:
```bash
sudo systemctl status revealer
sudo journalctl -u revealer -b
```


## Запуск скрипта на python


## Выпуск релиза
См. README_RELEASE