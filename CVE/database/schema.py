from pydantic import BaseModel, HttpUrl

rep = { "filename_cve": "CVE_start.zip",
        "filename_bdu_xml": "vulxml.xml",
        "update_url": "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_main1.zip",
        "name_base": "bd"
      }

class Repo_Schema(BaseModel):
    filename_cve: str
    filename_bdu_xml: str
    update_url: HttpUrl
    name_base: str  # без валидации названия бд
