def add_customer(db, email, phone):
    db.execute("INSERT INTO customers (email, phone) VALUES (?, ?)", (email, phone))


def anonymise_customer(db, customer_id):
    db.execute("UPDATE customers SET email = NULL, phone = NULL WHERE id = ?", (customer_id,))
