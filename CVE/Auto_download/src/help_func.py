import tempfile
from pathlib import Path
import requests
import json
import zipfile
from mongodb import base


def download_zip(repo_url: str, temp_path: Path):
    zip_path = temp_path / "download.zip"
    response = requests.get(repo_url, stream=True)
    response.raise_for_status()
    with open(zip_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    return zip_path

def update_in_mongo(update_url: str):
    with tempfile.TemporaryDirectory() as temp_file:
        temp_path = Path(temp_file)
        zip_path = download_zip(update_url, temp_path)
        extract_path = temp_path / "extracted"
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_path)
        collection_cve = base["CVE"]
        collection_bdu = base["BDU"]  # пока пустой
        successful_creates = 0
        successful_updates = 0
        errors = 0
        for file_path in extract_path.rglob("CVE*.json"):
            if file_path.is_file():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        json_data = json.load(f)
                    cve_id = json_data.get("cveMetadata", {}).get("cveId")
                    if not cve_id:
                        print(f"Ошибка: CVE ID не найден в файле {file_path.name}")
                        errors += 1
                        continue
                    result = collection_cve.update_one(
                        {"cveMetadata.cveId": cve_id},
                        {"$set": json_data},
                        upsert=True
                    )

                    if result.upserted_id is not None:
                        successful_creates += 1
                    elif result.modified_count > 0:
                        successful_updates += 1

                except Exception as e:
                    print(f"Ошибка в {file_path.name}: {e}")
                    errors += 1
        total_processed = successful_updates + successful_creates
        if total_processed == 0:
            return {
                "status": False,
                "message": "JSON-файлов с новыми данными о CVE не обнаружено."
            }
        return {
            "status": True,
            "message": "База данных успешно обновлена!",
            "statistics": {
                "Всего обработано файлов": total_processed,
                "Обновлённых документов": successful_updates,
                "Новых документов": successful_creates,
                "Ошибок": errors
            }
        }