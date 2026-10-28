#!/bin/zsh
# Build Java before authentication so downloads do not consume the sudo timeout.
cd -- "$(dirname -- "$0")" || exit 1
./scripts/build.sh -DskipTests || exit 1
print 'Net View: для чтения сетевых пакетов macOS нужен доступ администратора.'
print 'Пароль вводится в sudo; интерфейс приложения работает от обычного пользователя.'
if ! sudo -v; then
    print 'Захват не разрешён. Для просмотра сохранённых сеансов: ./scripts/run.sh'
    exit 1
fi
exec ./scripts/run.sh "$@"
