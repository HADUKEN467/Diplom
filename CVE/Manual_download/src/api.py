from fastapi import APIRouter
import requests
from schema import rep, Repo_Schema
from src.help_func import clone_cve_in_mongo, clone_bdu_xml_in_mongo
from mongodb import database_exists

router = APIRouter()
          
@router.post("/", summary="Скачать базу данных CVE и БДУ", tags=["CVE"])
async def download_base():
    """
    Скачивает базу данных CVE и сохраняет её в MongoDB
    """
    if not rep["filename_cve"] or not rep["filename_bdu"]:
        return {
            "status": False, 
            "message": "Не указано имя файла."
        }
    clone_result_cve = await clone_cve_in_mongo(rep["filename_cve"])
    clone_result_bdu = await clone_bdu_xml_in_mongo(rep["filename_bdu"])
    return clone_result_cve, clone_result_bdu
    
@router.post("/rep", summary="Установить конфигурацию базы данных", tags=["CVE"])
def setup_config(repo: Repo_Schema):
    """
    Устанавливает конфигурацию для базы данных CVE
    """
    try:
        if not repo.filename_bdu.endswith(".xml"):
            return {
                "status": False,
                "message": f"Имя файла в поле XML является именем файла недопустимого формата."
            }
        if not(repo.filename_cve.endswith(".zip") or
               repo.filename_cve.endswith(".rar") or
               repo.filename_cve.endswith(".7z") or
               repo.filename_cve.endswith(".tar")):
            return {
                "status": False,
                "message": f"Имя файла в поле СЖАТЫЙ ФАЙЛ является именем файла недопустимого формата."
            }
        response_update = requests.head(str(repo.update_url_cve), allow_redirects=True, timeout=10)
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


