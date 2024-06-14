@echo off

:parse

    if /i "%~1"=="--ipv4"     set "IPAddress=%~2"   & shift & shift & goto :parse
	if /i "%~1"=="--interface"     set "InterfaceName=%~2"   & shift & shift & goto :parse
	if /i "%~1"=="--dhcp"     set "DHCP=%~2"   & shift & shift & goto :parse
	if /i "%~1"=="--netmask"     set "SubnetMask=%~2"   & shift & shift & goto :parse
	if /i "%~1"=="--gateway"     set "GatewayAddress=%~2"   & shift & shift & goto :parse
	if /i "%~1"=="--help"     set "Help=%~1"   & shift & shift & goto :parse

:main
    if defined Help   echo %usage%
 
    if defined InterfaceName             echo Interface name:          %InterfaceName%
	if not defined InterfaceName         echo Interface name:          not provided

	if defined DHCP               echo DHCP enabled:          %DHCP%
	if not defined DHCP           echo DHCP enabled:          not provided
	
	if defined IPAddress               echo IPv4 address:          %IPAddress%
	if not defined IPAddress           echo IPv4 address:          not provided
	
	if defined SubnetMask               echo Subnet mask:          %SubnetMask%
	if not defined SubnetMask           echo Subnet mask:          not provided
	
	if defined GatewayAddress               echo Gateway address:          %GatewayAddress%
	if not defined GatewayAddress           echo Gateway address:          not provided
