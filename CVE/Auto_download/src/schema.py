from pydantic import BaseModel, HttpUrl

rep = {"repo_url": "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_start.zip",
       "update_url": "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_main1.zip",
       "name_base": "cve_bd"
      }

class Repo_Schema(BaseModel):
    repo_url: HttpUrl
    update_url: HttpUrl
    name_base: str  # без валидации названия бд
