from flask import Flask, render_template, request, redirect, jsonify, url_for
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from model import Base, Item, Category

app = Flask(__name__)

engine = create_engine('sqlite:///item-catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/items.json')
@app.route('/catalog.json')
def itemsJSON():
    items = session.query(Item).all()
    return jsonify(Catalog=[i.serialize for i in items])


# Show all items
@app.route('/')
@app.route('/catalog/')
def show_items():
    # Latest 10 items
    items = session.query(Item).order_by(desc(Item.id)).limit(10)
    categories = session.query(Category).all()
    return render_template('items.html', items=items, categories=categories)


# Show items in a category
@app.route('/catalog/<int:category_id>/items')
def show_items_category(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    categories = session.query(Category).all()
    return render_template('items_category.html',
                           items=items,
                           categories=categories,
                           category=category)


# Show an item
@app.route('/catalog/<int:category_id>/item/<int:item_id>')
def show_item(category_id, item_id):
    item_to_show = session.query(Item).filter_by(id=item_id).one()
    return render_template('show_item.html', item=item_to_show)


# Add an item
@app.route('/catalog/add/', methods=['GET', 'POST'])
def add_item():
    if request.method == 'POST':
        item_name = request.form['name']
        item_info = request.form['info']
        item_category_id = request.form['category']
        item_to_add = Item(
            name=item_name, info=item_info, category_id=item_category_id)
        session.add(item_to_add)
        session.commit()
        return redirect(url_for('show_items'))
    else:
        print('get')
        categories = session.query(Category).all()
        return render_template('add_item.html', categories=categories)


# Edit an item
@app.route('/catalog/<int:category_id>/item/<int:item_id>/edit/', methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    item_to_edit = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        if request.form['name']:
            item_to_edit.name = request.form['name']
            item_to_edit.info = request.form['info']
            item_to_edit.category_id = request.form['category']
            session.commit()
            return redirect(url_for('show_items'))
    else:
        categories = session.query(Category).all()
        return render_template(
            'edit_item.html', item=item_to_edit, categories=categories)


# Delete an item
@app.route('/catalog/<int:category_id>/item/<int:item_id>/delete/', methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    item_to_delete = session.query(
        Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(item_to_delete)
        session.commit()
        return redirect(url_for('show_items'))
    else:
        return render_template(
            'delete_item.html', item=item_to_delete)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
