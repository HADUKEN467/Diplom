from fastapi import APIRouter
import requests
from schema import rep, Repo_Schema
from src.help_func import update_in_mongo
from mongodb import database_exists

router = APIRouter()


@router.post("/rep", summary="Установить конфигурацию базы данных", tags=["CVE"])
def setup_config(repo: Repo_Schema):
    """
    Устанавливает конфигурацию для базы данных CVE
    """
    try:
        response_update = requests.head(str(repo.update_url), allow_redirects=True, timeout=10)
        if response_update.status_code != 200:
            return {
                "status": False,
                "message": f"Файл для обновлений недоступен. Статус: {response_update.status_code}"
            }
        content_type_download = response_update.headers.get("Content-Type", "").lower()
        valid_zip_types = [
            "application/zip",
            "application/x-zip-compressed",
            "application/octet-stream"
        ]

        if not any(zip_type in content_type_download for zip_type in valid_zip_types):
            return {
                "status": False,
                "message": f"Ссылка для скачивания ведёт не на zip-файл. Content-Type: {content_type_download}"
            }
        rep["filename"] = repo.filename
        rep["update_url"] = repo.update_url.unicode_string()
        rep["name_base"] = repo.name_base

        return {
            "status": True,
            "message": "Конфигурация базы данных обновлена",
            "config": {
                "filename": rep["filename"],
                "update_url": rep["update_url"],
                "name_base": rep["name_base"]
            }
        }

    except requests.exceptions.ConnectionError:
        return {
            "status": False,
            "message": "Не удалось подключиться к серверу. Проверьте URL и интернет-соединение."
        }

    except requests.exceptions.Timeout:
        return {
            "status": False,
            "message": "Таймаут подключения. Сервер не ответил вовремя."
        }

    except requests.exceptions.RequestException as e:
        return {
            "status": False,
            "message": f"Ошибка при проверке ссылки: {str(e)}"
        }

    except Exception as e:
        return {
            "status": False,
            "message": f"Неизвестная ошибка: {str(e)}"
        }

@router.put("/rep", summary="Обновить базу данных CVE и БДУ", tags=["CVE"])
async def update_base():
    """
    Обновляет существующую базу данных CVE и BDU в MongoDB
    """
    if not database_exists(rep["name_base"]):
        return {
            "status": False, 
            "message": 'База данных пуста. Используйте POST "Скачать базу данных CVE и БДУ"'
        }
    update_url = rep.get("update_url")
    if not update_url:
        return {
            "status": False,
            "message": "URL для обновления не настроен. Проверьте конфигурацию."
        }
    
    update_result = update_in_mongo(update_url)
    return update_result


