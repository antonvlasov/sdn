from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel
import random

app = FastAPI()


class Item(BaseModel):
    name: str
    price: float
    is_offer: Optional[bool] = None


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Optional[str] = None):
    return {"item_id": item_id, "q": q}


@app.post("/items/{item_id}")
def update_item(item_id: int, item: Item):
    k = random.random()*2+0.2
    print(item)
    return {"item_price": int(item.price*k), "item_id": item_id}
