`{`
    `"dataType": "CVE_RECORD", // Тип данных - запись об уязвимости CVE`
    `"dataVersion": "5.1", // Версия формата данных`
    `"cveMetadata": { // Метаданные CVE`
        `"cveId": "CVE-2025-0062", // Идентификатор уязвимости`
        `"assignerOrgId": "e4686d1a-f260-4930-ac4c-2f5c992778dd", // ID организации, назначившей CVE`
        `"state": "PUBLISHED", // Статус - опубликовано`
        `"assignerShortName": "sap", // Короткое имя назначившей организации - SAP`
        `"dateReserved": "2024-12-05T21:53:05.819Z", // Дата резервирования CVE`
        `"datePublished": "2025-03-11T00:31:18.755Z", // Дата публикации`
        `"dateUpdated": "2025-03-11T02:18:37.752Z" // Дата последнего обновления`
    `},`
    `"containers": { // Контейнеры с основной информацией`
        `"cna": { // Основная информация от CNA (CVE Numbering Authority)`
            `"affected": [ // Список затронутых продуктов`
                `{`
                    `"defaultStatus": "unaffected", // Статус по умолчанию - не затронут`
                    `"product": "SAP BusinessObjects Business Intelligence Platform", // Название продукта`
                    `"vendor": "SAP_SE", // Производитель`
                    `"versions": [ // Список версий`
                        `{`
                            `"status": "affected", // Статус - затронута`
                            `"version": "ENTERPRISE 430" // Версия продукта`
                        `},`
                        `{`
                            `"status": "affected",`
                            `"version": "2025"`
                        `},`
                        `{`
                            `"status": "affected",`
                            `"version": "ENTERPRISECLIENTTOOLS 430"`
                        `}`
                    `]`
                `}`
            `],`
            `"descriptions": [ // Описания уязвимости`
                `{`
                    `"lang": "en", // Язык описания - английский`
                    `"supportingMedia": [ // Дополнительные медиа-данные`
                        `{`
                            `"base64": false, // Не в формате base64`
                            `"type": "text/html", // Тип - HTML текст`
                            `"value": "<p>SAP BusinessObjects Business Intelligence Platform allows an attacker to inject JavaScript code in Web Intelligence reports. This code is then executed in the victim's browser each time the vulnerable page is visited by the victim. On successful exploitation, an attacker could cause limited impact on confidentiality and integrity within the scope of victim�s browser. There is no impact on availability. This vulnerability occurs only when script/html execution is enabled by the administrator in Central Management Console.</p>"`
                            `// HTML описание уязвимости: XSS в Web Intelligence отчетах`
                        `}`
                    `],`
                    `"value": "SAP BusinessObjects Business Intelligence Platform allows an attacker to inject JavaScript code in Web Intelligence reports. This code is then executed in the victim's browser each time the vulnerable page is visited by the victim. On successful exploitation, an attacker could cause limited impact on confidentiality and integrity within the scope of victim�s browser. There is no impact on availability. This vulnerability occurs only when script/html execution is enabled by the administrator in Central Management Console."`
                    `// Текстовое описание: XSS уязвимость при включенном выполнении скриптов`
                `}`
            `],`
            `"metrics": [ // Метрики оценки уязвимости`
                `{`
                    `"cvssV3_1": { // CVSS версия 3.1`
                        `"attackComplexity": "HIGH", // Высокая сложность атаки`
                        `"attackVector": "NETWORK", // Вектор атаки - через сеть`
                        `"availabilityImpact": "NONE", // Нет влияния на доступность`
                        `"baseScore": 4.7, // Базовая оценка - 4.7/10`
                        `"baseSeverity": "MEDIUM", // Уровень опасности - средний`
                        `"confidentialityImpact": "LOW", // Низкое влияние на конфиденциальность`
                        `"integrityImpact": "LOW", // Низкое влияние на целостность`
                        `"privilegesRequired": "NONE", // Привилегии не требуются`
                        `"scope": "CHANGED", // Область воздействия изменена`
                        `"userInteraction": "REQUIRED", // Требуется взаимодействие пользователя`
                        `"vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", // Векторная строка CVSS`
                        `"version": "3.1" // Версия CVSS`
                    `},`
                    `"format": "CVSS", // Формат метрики - CVSS`
                    `"scenarios": [ // Сценарии оценки`
                        `{`
                            `"lang": "en", // Язык - английский`
                            `"value": "GENERAL" // Общий сценарий`
                        `}`
                    `]`
                `}`
            `],`
            `"problemTypes": [ // Типы проблем/уязвимостей`
                `{`
                    `"descriptions": [ // Описания типа проблемы`
                        `{`
                            `"cweId": "CWE-79", // ID уязвимости по CWE - 79 (XSS)`
                            `"description": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", // Описание - недостаточная нейтрализация ввода (XSS)`
                            `"lang": "eng", // Язык - английский`
                            `"type": "CWE" // Тип - CWE`
                        `}`
                    `]`
                `}`
            `],`
            `"providerMetadata": { // Метаданные провайдера`
                `"orgId": "e4686d1a-f260-4930-ac4c-2f5c992778dd", // ID организации`
                `"shortName": "sap", // Короткое имя - SAP`
                `"dateUpdated": "2025-03-11T00:31:18.755Z" // Дата обновления`
            `},`
            `"references": [ // Ссылки на дополнительную информацию`
                `{`
                    `"url": "https://me.sap.com/notes/3557459" // Ссылка на примечание SAP`
                `},`
                `{`
                    `"url": "https://url.sap/sapsecuritypatchday" // Ссылка на день патчей безопасности SAP`
                `}`
            `],`
            `"source": { // Источник информации`
                `"discovery": "UNKNOWN" // Неизвестно кто обнаружил`
            `},`
            `"title": "Cross-Site Scripting (XSS) vulnerability in SAP BusinessObjects Business Intelligence Platform (Web Intelligence)", // Заголовок - XSS уязвимость`
            `"x_generator": { // Генератор документа`
                `"engine": "Vulnogram 0.2.0" // Использован Vulnogram версии 0.2.0`
            `}`
        `},`
        `"adp": [ // Дополнительные данные от CISA ADP`
            `{`
                `"metrics": [ // Метрики оценки`
                    `{`
                        `"other": { // Другие метрики`
                            `"type": "ssvc", // Тип - SSVC (Stakeholder-Specific Vulnerability Categorization)`
                            `"content": { // Содержимое SSVC`
                                `"timestamp": "2025-03-11T02:18:19.810551Z", // Временная метка`
                                `"id": "CVE-2025-0062", // ID CVE`
                                `"options": [ // Опции оценки`
                                    `{`
                                        `"Exploitation": "none" // Эксплуатация - отсутствует`
                                    `},`
                                    `{`
                                        `"Automatable": "no" // Автоматизация - нет`
                                    `},`
                                    `{`
                                        `"Technical Impact": "partial" // Техническое воздействие - частичное`
                                    `}`
                                `],`
                                `"role": "CISA Coordinator", // Роль - координатор CISA`
                                `"version": "2.0.3" // Версия SSVC`
                            `}`
                        `}`
                    `}`
                `],`
                `"title": "CISA ADP Vulnrichment", // Заголовок - обогащение данных от CISA ADP`
                `"providerMetadata": { // Метаданные провайдера`
                    `"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0", // ID организации CISA`
                    `"shortName": "CISA-ADP", // Короткое имя - CISA ADP`
                    `"dateUpdated": "2025-03-11T02:18:37.752Z" // Дата обновления`
                `}`
            `}`
        `]`
    `}`
`}`