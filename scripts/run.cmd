@echo off
cd /d "%~dp0.."
if not exist target\net-view-0.5.0.jar (
  call mvn package
  if errorlevel 1 exit /b 1
)
java --enable-native-access=ALL-UNNAMED "-Djavafx.cachedir=%CD%\.cache\javafx" "-Dnetview.projectDir=%CD%" -jar target\net-view-0.5.0.jar %*
