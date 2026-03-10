from fastapi import FastAPI, HTTPException
import uvicorn
from pydantic import BaseModel

app = FastAPI()

id_sp = [1, 2]
sp = [{
    "id": 1,
    "name": "Андрей",
    "specialization": "DevOps"
},
    {
    "id": 2,
    "name": "Игорь",
    "specialization": "Backend-developer",
}]


@app.get("/sp", summary="Получить полный список людей", tags=["Люди👦"])
def people():
    return sp


@app.get("/sp/name/{name}", summary="Найти человека по имени", tags=["Люди👦"])
def people_by_name(name: str):
    for person in sp:
        if person.get("name") == name:
            return person
    raise HTTPException(status_code=404,
                        detail="Человек с таким именем не найден!")


@app.get("/sp/id/{id}", summary="Найти человека по ID", tags=["Люди👦"])
def people_by_id(id: int):
    for person in sp:
        if person.get("id") == id:
            return person
    raise HTTPException(status_code=404,
                        detail="Человек с таким ID не найден!")


class NewPeople(BaseModel):
    name: str
    specialization: str


@app.post("/sp", summary="Добавить нового человека", tags=["Люди👦"])
def create_people(newppl: NewPeople):
    if len(sp) != 0:
        id_sp.append(sp[-1]["id"] + 1)
        sp.append({
            "id": sp[-1]["id"] + 1,
            "name": newppl.name,
            "specialization": newppl.specialization
            })
        return {"success": True, "id": sp[-1]["id"],
                "message": "Человек успешно добавлен!"}
    id_sp.append(1)
    sp.append({
        "id": 1,
        "name": newppl.name,
        "specialization": newppl.specialization
        })
    return {"success": True, "id": 1,
            "message": "Человек успешно добавлен!"}


@app.delete("/sp/id/{id}", summary="Удалить человека через ID", tags=["Люди👦"])
def delete_people(id: int):
    if len(sp) != 0 and id >= 1 and id in id_sp:
        removed_id = [i for i, elem in enumerate(sp) if elem.get("id") == id]
        removed_ppl = sp.pop(removed_id[0])
        id_sp.remove(id)
        return {"success": True,
                "removed_people": removed_ppl,
                "message": "Человек успешно удалён!"}
    raise HTTPException(status_code=404, detail="Такого ID не существует!")


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
