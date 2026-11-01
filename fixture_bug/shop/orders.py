from shop.keys import sign

ORDERS = {}


def place_order(user_id, items, key):
    total = sum(item["price"] * item["quantity"] for item in items)
    order_id = str(len(ORDERS) + 1)
    ORDERS[order_id] = {"user_id": user_id, "total": total, "refunded": 0, "status": "paid"}
    ORDERS[order_id]["receipt"] = sign(key, order_id)
    return {"order_id": order_id, "total": total}
