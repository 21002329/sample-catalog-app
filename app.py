from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
from flask import make_response
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import random
import string
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from model import Base, Item, Category

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

app = Flask(__name__)

engine = create_engine('sqlite:///item-catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/items.json')
@app.route('/catalog.json')
def itemsJSON():
    """JSON endpoint"""
    items = session.query(Item).all()
    return jsonify(Catalog=[i.serialize for i in items])


@app.route('/login')
def show_login():
    """Login"""
    state = ''.join(random.choice(string.ascii_uppercase + string.
                                  digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, logged_in=app.logged_in)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode('utf-8'))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    app.logged_in = True

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        app.logged_in = False
        return redirect(url_for('show_items'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@app.route('/catalog/')
def show_items():
    # Latest 10 items
    items = session.query(Item).order_by(desc(Item.id)).limit(10)
    categories = session.query(Category).all()
    return render_template('items.html',
                           items=items,
                           categories=categories,
                           logged_in=app.logged_in)


@app.route('/catalog/<int:category_id>/items')
def show_items_category(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    categories = session.query(Category).all()
    return render_template('items_category.html',
                           items=items,
                           categories=categories,
                           category=category,
                           logged_in=app.logged_in)


@app.route('/catalog/<int:category_id>/item/<int:item_id>')
def show_item(category_id, item_id):
    item_to_show = session.query(Item).filter_by(id=item_id).one()
    return render_template('show_item.html',
                           item=item_to_show,
                           logged_in=app.logged_in)


@app.route('/catalog/add/', methods=['GET', 'POST'])
def add_item():
    if 'username' not in login_session:
        return redirect('/login')
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
        return render_template('add_item.html',
                               categories=categories,
                               logged_in=app.logged_in)


@app.route('/catalog/<int:category_id>/item/<int:item_id>/edit/', methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
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
        return render_template('edit_item.html',
                               item=item_to_edit,
                               categories=categories,
                               logged_in=app.logged_in)


@app.route('/catalog/<int:category_id>/item/<int:item_id>/delete/', methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    item_to_delete = session.query(
        Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(item_to_delete)
        session.commit()
        return redirect(url_for('show_items'))
    else:
        return render_template('delete_item.html',
                               item=item_to_delete,
                               logged_in=app.logged_in)


if __name__ == '__main__':
    app.secret_key = "Secret Key"
    app.logged_in = False
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
