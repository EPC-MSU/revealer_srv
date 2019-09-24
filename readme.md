# md_revealer_srv

Revealer ПО, которое позволяет находить наши устройства в сети.

https://doc.xisupport.com/ru/8smc5-usb/8SMCn-USB/Related_products/Control_via_Ethernet/Web_interface.html#automatic-device-detection

http://files.xisupport.com/Software.ru.html#revealer-0.1.0-last-updated-16.04.2017



Как это работает: 

* на каждом устройстве запускается сервер;

* программа ревилер шлёт широковещательный пакет в сеть;

* при получении этого пакета сервера на устройствах отвечают ревилеру;

* ревилер смотрит, кто ему ответил, и составляет список устройств.

 

В данном репозитории хранится простой сервер на python, который позволяет отвечать клиентам-ревилерам.

 

## Руководство по запуску

 