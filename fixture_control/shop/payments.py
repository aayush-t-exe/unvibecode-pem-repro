from shop.orders import ORDERS


def send_money_to_customer(user_id, amount):
    print(f"paying {amount} to {user_id}")


def refund_order(order_id, amount):
    order = ORDERS[order_id]
    # The refund is paid out before checking how much was already refunded,
    # and the requested amount is never compared with the order total.
    send_money_to_customer(order["user_id"], amount)
    order["refunded"] += amount
    order["status"] = "refunded"
    return {"order_id": order_id, "refunded": order["refunded"]}
