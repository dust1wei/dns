@echo off
setlocal
where gcc >nul 2>nul
if errorlevel 1 (
  echo gcc not found. Install MinGW-w64 and add gcc to PATH.
  exit /b 1
)
where windres >nul 2>nul
if errorlevel 1 (
  echo windres not found. Install the MinGW-w64 bin tools and add them to PATH.
  exit /b 1
)

echo Building console version...
gcc -O2 -Wall -Wextra -std=c11 -D_WIN32_WINNT=0x0600 dns_optimizer.c -o dns_optimizer.exe -lws2_32 -liphlpapi
if errorlevel 1 exit /b 1

echo Building Windows GUI...
windres app.rc -O coff -o app_res.o
if errorlevel 1 exit /b 1
gcc -O2 -Wall -Wextra -std=c11 -D_WIN32_WINNT=0x0600 -mwindows dns_optimizer_gui.c app_res.o -o dns_optimizer_gui.exe -lws2_32 -liphlpapi -ladvapi32 -luser32
if errorlevel 1 exit /b 1

del app_res.o >nul 2>nul
echo Built dns_optimizer.exe and dns_optimizer_gui.exe
