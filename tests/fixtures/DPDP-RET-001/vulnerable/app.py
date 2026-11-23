def add_customer(db, email, phone):
    db.execute("INSERT INTO customers (email, phone) VALUES (?, ?)", (email, phone))


def cancel_order(db, order_id):
    db.execute("DELETE FROM orders WHERE id = ?", (order_id,))
