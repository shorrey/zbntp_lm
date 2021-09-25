# zbntp_lm - Zabbix NTP Loadable Module
Подгружаемый модуль Zabbix для мониторинга NTP-серверов путём посылки простого запроса и анализа ответа.

- Почему не понравилось парсить вывод команды, например, "ntpdate -q"  
потому что каждый запрос будет порождать форки. Хоть это обычно и не
является большой нагрузкой на сервер, считаю саму идею ущербной.

- Почему именно анализ ответа сервера, а не реализация chronyc или ntpq, например  
потому что это должно стать простым и универсальным средством
проверки работоспособности и качества сервиса. Независимо от его реализации.
По этой же причине не понравился анализ журналов соответствующих приложений, хотя он мог бы дать много дополнительной информации.

- Почему не понравился стандартный шаблон "NTP Service"  
потому что он определяет только факт ответа на запрос, а что там внутри... А ведь NTP-сервер
со stratum=16 тоже будет отвечать.

- Почему внутри должен быть кеш ответов  
потому что каждый ответ даёт множество метрик. Если пользователь решит получать все доступные метрики, на
каждый запрос метрики должен быть послан отдельный, но идентичный запрос серверу. А "спамить" NTP-сервера также некрасиво, как запускать внешние бинарники.