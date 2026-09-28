#!/usr/bin/env bash
# Запуск из Git Bash в Windows; работает также в Linux и macOS.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -z "${SPORTMEET_DB:-}" && ! -f instance/sportmeet.sqlite3 ]]; then
  printf '%s\n' 'Не найдена основная база instance/sportmeet.sqlite3.' \
    'Распакуйте архив целиком в новую папку и запустите скрипт из папки sportmeet.' >&2
  exit 1
fi

if command -v py >/dev/null 2>&1 && py -3 -c 'import sys; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
  python_launcher=(py -3)
elif command -v python >/dev/null 2>&1 && python -c 'import sys; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
  python_launcher=(python)
elif command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
  python_launcher=(python3)
else
  printf '%s\n' 'Не найден Python 3.11 или новее.' \
    'Установите Python с python.org, отметьте «Add python.exe to PATH»,' \
    'закройте Git Bash, откройте его снова и повторите запуск.' >&2
  exit 1
fi

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) venv_python='.venv/Scripts/python.exe' ;;
  *) venv_python='.venv/bin/python' ;;
esac

if [[ ! -f "$venv_python" ]]; then
  printf '%s\n' 'Создаю виртуальное окружение .venv ...'
  "${python_launcher[@]}" -m venv .venv
fi
if [[ ! -f "$venv_python" ]]; then
  printf '%s\n' 'Не удалось создать .venv. Проверьте установленный Python и права записи в эту папку.' >&2
  exit 1
fi

if ! "$venv_python" -c 'import flask, pytest, pymongo; from zoneinfo import ZoneInfo; ZoneInfo("Europe/Moscow")' >/dev/null 2>&1; then
  printf '%s\n' 'Устанавливаю недостающие зависимости (нужен интернет) ...'
  "$venv_python" -m pip install -r requirements.txt
fi

"$venv_python" -m flask --app app init-db
venue_count="$("$venv_python" -c 'import sqlite3; from app import app; print(sqlite3.connect(app.config["DATABASE"]).execute("SELECT COUNT(*) FROM venues").fetchone()[0])')"
if [[ "$venue_count" == '0' ]]; then
  printf '%s\n' 'Импортирую 4751 спортивную площадку ...'
  "$venv_python" -m flask --app app import-venues
else
  contact_count="$("$venv_python" -c 'import sqlite3; from app import app; print(sqlite3.connect(app.config["DATABASE"]).execute("SELECT COUNT(*) FROM venues WHERE website IS NOT NULL").fetchone()[0])')"
  if [[ "$contact_count" == '0' ]]; then
    printf '%s\n' 'Добавляю контакты и пояснения к стоимости в существующую базу ...'
    "$venv_python" -m flask --app app import-venues
  fi
fi

printf '\n%s\n' 'Откройте в браузере http://127.0.0.1:5000' \
  'Для остановки сервера нажмите Ctrl+C в этом окне.' \
  'Учётные записи для проверки ролей перечислены в УЧЁТНЫЕ_ЗАПИСИ.md.'
exec "$venv_python" -m flask --app app run --host 127.0.0.1 --port 5000
