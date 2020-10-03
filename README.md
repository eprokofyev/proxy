# proxy

## Требования
* mongo на порту 27017

 ## Запуск
 * go run cmd/ca_generator/generator.go - генерация сертификата
 * go run cmd/server/server.go - запуск proxy-сервера
 * go run cmd/repeater/repeater.go - запуск повторителя запросов
 
 ## Использование
 * Добавить сгенерированный сертификат в браузер
 * 127.0.0.1/requests - список запросов с уязвимостями
 * 127.0.0.1/requests/id - повтор запроса
