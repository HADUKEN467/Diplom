from fastapi import APIRouter
import requests
from schema import rep, Repo_Schema
from src.help_func import update_cve_in_mongo, update_bdu_in_mongo
from mongodb import database_exists

router = APIRouter()


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
    update_url_cve = rep.get("update_url_cve")
    update_url_bdu = rep.get("update_url_bdu")
    if not update_url_cve or not update_url_bdu:
        return {
            "status": False,
            "message": "URL для обновления не настроен. Проверьте конфигурацию."
        }
    
    update_cve_result = await update_cve_in_mongo(update_url_cve)
    update_bdu_result = await update_bdu_in_mongo(update_url_bdu)
    return update_cve_result, update_bdu_result


@router.post("/rep", summary="Установить конфигурацию базы данных", tags=["CVE"])
async def setup_config(repo: Repo_Schema):
    """
    Устанавливает конфигурацию для базы данных CVE
    """
    try:
        if not repo.filename_bdu.endswith(".xml"):
            return {
                "status": False,
                "message": f"Имя файла в поле XML является именем файла недопустимого формата."
            }
        if not (repo.filename_cve.endswith((".zip"))):
            return {
                "status": False,
                "message": f"Имя файла в поле СЖАТЫЙ ФАЙЛ является именем файла недопустимого формата."
            }
        response_update1 = requests.head(str(repo.update_url_cve),
                                         allow_redirects=True,
                                         timeout=10,
                                         verify=False)
        if response_update1.status_code != 200:
            return {
                "status": False,
                "message": f"Файл для обновлений CVE недоступен. Статус: {response_update1.status_code}"
            }
        content_type_cve = response_update1.headers.get("Content-Type", "").lower()
        valid_archive_types = [
            "application/zip",
            "application/x-zip-compressed",
            "application/octet-stream"
        ]
        if not any(archive_type in content_type_cve for archive_type in valid_archive_types):
            return {
                "status": False,
                "message": f"Ссылка CVE ведёт не на архив. Content-Type: {content_type_cve}"
            }
        response_update2 = requests.head(str(repo.update_url_bdu),
                                         allow_redirects=True,
                                         timeout=10,
                                         verify=False)  # ← SSL отключение
        if response_update2.status_code != 200:
            return {
                "status": False,
                "message": f"Файл для обновлений BDU недоступен. Статус: {response_update2.status_code}"
            }

        content_type_bdu = response_update2.headers.get("Content-Type", "").lower()
        valid_bdu_types = [
            "application/xml",
            "text/xml",
            "application/zip",
            "application/x-zip-compressed",
            "application/octet-stream"
        ]
        if not any(bdu_type in content_type_bdu for bdu_type in valid_bdu_types):
            return {
                "status": False,
                "message": f"Ссылка BDU должна вести на XML или ZIP. Content-Type: {content_type_bdu}"
            }

        rep["filename_cve"] = repo.filename_cve
        rep["filename_bdu"] = repo.filename_bdu
        rep["update_url_cve"] = repo.update_url_cve.unicode_string()
        rep["update_url_bdu"] = repo.update_url_bdu.unicode_string()
        rep["name_base"] = repo.name_base

        return {
            "status": True,
            "message": "Конфигурация базы данных обновлена",
            "config": {
                "filename_cve": rep["filename_cve"],
                "filename_bdu": rep["filename_bdu"],
                "update_url_cve": rep["update_url_cve"],
                "update_url_bdu": rep["update_url_bdu"],
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


