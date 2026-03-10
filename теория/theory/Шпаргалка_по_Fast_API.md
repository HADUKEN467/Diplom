Для запуска серверов (дока, аппка) из терминала (из нужной директории):
	`py -m uvicorn main:app --reload`
	`py -m fastapi dev main.py` 
Или "адекватный" способ:
	`import uvicorn`
	`if __name__ == "__main__":`
	    `uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)`
