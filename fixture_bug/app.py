from flask import Flask, jsonify, request

from shop.keys import load_signing_key
from shop.orders import place_order
from shop.payments import refund_order

app = Flask(__name__)
SIGNING_KEY = load_signing_key(open("signing.pem").read())


@app.post("/orders")
def create_order():
    body = request.get_json()
    order = place_order(body["user_id"], body["items"], SIGNING_KEY)
    return jsonify(order)


@app.post("/orders/<order_id>/refund")
def refund(order_id):
    body = request.get_json()
    return jsonify(refund_order(order_id, body["amount"]))
