@echo off
setlocal
set "ROOT=%~dp0"
python "%ROOT%src\reconscope.py" %*
endlocal
