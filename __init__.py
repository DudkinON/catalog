#!/usr/bin/env python
# -*- coding: utf-8 -*-

from functools import wraps
from flask import Flask, jsonify, request, g, render_template as render, flash
from flask import session, redirect
from models import create_user, get_user_by_username, create_category
from models import create_item, User, get_items_by_category, update_user_photo
from models import get_categories, get_items, get_user_by_email, check_category
from models import user_exist, update_user, remove_user, get_user_by_id
from models import add_images, get_items_by_user, update_item, get_item_by_id
from models import delete_item, email_exist, get_images_by_item_id
from models import remove_images_by_item_id
from data_control import email_is_valid, get_unique_str, get_path, allowed_file
from settings import *
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from bleach import clean
from httplib2 import Http
from flask import make_response
from requests import get as r_get
from json import dumps, loads
from re import findall

ALLOWED_EXTENSIONS = set(EXTENSIONS)
auth = HTTPBasicAuth()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

brands = get_categories()
csrf_token = get_unique_str(32)


# TODO: Login required
def login_required(f):
    """
    Checking the user is logged in

    :param f:
    :return:
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'uid' in session:
            return f(*args, **kwargs)
        else:
            flash('You are not allowed to access there', 'error')
            return redirect('/login', 302)

    return decorated_function


# TODO: Verification of password
@auth.verify_password
def verify_password(_login, password):
    """
    Verification of password

    :param _login:
    :param password:
    :return bool:
    """
    # Try to see if it's a token first
    user_id = User.verify_auth_token(_login)
    if user_id:
        user = get_user_by_id(user_id)
    else:
        user = get_user_by_email(_login)
        if not user:
            user = get_user_by_username(_login)
            if not user or not user.verify_password(password):
                return False
        else:
            if not user.verify_password(password):
                return False
    g.user = user
    return True


@app.route('/')
def home_page():
    """
    Main page

    :return:
    """
    title = 'Home page'
    cars = [item.serialize for item in get_items(9)]
    return render('catalog/index.html', brands=brands, cars=cars, title=title)


@app.route('/login')
def sign_in():
    """
    Sign in page

    :return:
    """
    title = 'Sign in'
    return render('/users/login.html', brands=brands, title=title)


@app.route('/profile')
@login_required
def user_profile():
    """
    Profile page

    :return:
    """
    user = get_user_by_id(session['uid'])
    title = '%s - profile' % user.get_full_name
    cars = [item.serialize for item in get_items_by_user(session['uid'])]
    print cars
    return render('/users/profile.html',
                  brands=brands,
                  title=title,
                  cars=cars,
                  user=user.serialize)


@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_user_profile():
    """
    Edit user profile

    :return mix:
    """

    # check if user is logged in
    if not session.get('uid'):
        return redirect('/login', 302)

    # get user
    user = get_user_by_id(session['uid'])

    # POST request
    if request.method == 'POST' and request.form['csrf_token'] == csrf_token:

        # cleaning data
        try:
            _user = dict()
            _user['uid'] = int(session['uid'])
            _user['username'] = clean(request.form['username'])
            _user['first_name'] = clean(request.form['first_name'])
            _user['last_name'] = clean(request.form['last_name'])
            _user['email'] = clean(request.form['email'])
        except TypeError:
            flash('Fields can\'t be empty', 'error')
            return redirect('/profile', 302)

        if email_is_valid(_user['email']):
            user = update_user(_user)
            full_name = ' '.join([user.first_name, user.last_name])
            message = 'Dear %s, your information was updating' % full_name
            flash(message, 'success')
            return redirect('/profile', 302)
        else:
            flash('Invalid email', 'error')
            return render('users/edit_profile.html',
                          brands=brands,
                          user=user,
                          csrf_token=csrf_token)

    return render('users/edit_profile.html',
                  brands=brands,
                  token=user.generate_auth_token(3600),
                  user=user,
                  csrf_token=csrf_token)


@app.route('/profile/delete', methods=['GET', 'POST'])
@login_required
def remove_profile():
    """
    Remove user profile

    :return mix:
    """

    # get uid
    uid = int(session['uid'])

    # get user items
    items = [item.serialize for item in get_items_by_user(uid)]

    # if the user have any items create message
    if len(items) > 0:
        flash('First remove your cars', 'error')

    # get user
    user = get_user_by_id(uid)

    # get user full name
    name = ' '.join([user.first_name, user.last_name])

    if request.method == 'POST' and request.form['csrf_token'] == csrf_token:

        if len(items) > 0:
            return render('users/delete_profile.html',
                          brands=brands, csrf_token=csrf_token)

        # get absolute path to image
        path = ''.join([BASE_DIR, user.picture])

        # if file exist remove the image file
        if os.path.isfile(path):
            os.unlink(path)

        # remove user data from database
        remove_user(uid)

        # remove session
        del session['uid']

        if 'provider' in session:
            del session['provider']

        # create success message
        flash('Profile "%s" was removed' % name, 'success')

        # redirect user to home page
        return redirect('/', 302)

    return render('users/delete_profile.html',
                  brands=brands, csrf_token=csrf_token)


@app.route('/brand/<int:brand_id>')
def cars_by_brand(brand_id):
    """
    Brand page

    :param brand_id: int
    :return:
    """
    cars = [car.serialize for car in get_items_by_category(brand_id, 9)]
    return render('catalog/brand.html', brands=brands, cars=cars)


@app.route('/car/<int:item_id>')
def show_car(item_id):
    """
    Show car page
    :param item_id: int
    :return:
    """
    car = get_item_by_id(item_id)
    return render('catalog/car.html', brands=brands, car=car.serialize)


@app.route('/new/car', methods=['GET', 'POST'])
@login_required
def new_car():
    """
    Create a new car

    :return mix:
    """

    # POST request
    if request.method == 'POST' and request.form['csrf_token'] == csrf_token:

        # Get and clean data
        try:
            title = clean(request.form.get('title'))
            model = clean(request.form.get('model'))
            description = clean(request.form.get('description'))
            brand = clean(request.form.get('brand'))
            price = clean(request.form.get('price'))
            author = session.get('uid')
        except TypeError:
            flash('fields can\'t be empty', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)

        # check data
        if len(title) < 5:
            flash('too short title, minimum 5 characters', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)
        if len(title) > 250:
            flash('too long title, maximum 250 characters', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)
        if len(model) < 2:
            flash('too short model, minimum 2 characters', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)
        if len(model) > 100:
            flash('too long model, maximum 100 characters', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)
        if len(description) < 5:
            flash('too short description, min 5 symbols', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)
        if len(description) > 250:
            flash('too long description, maximum 250 symbols', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)

        # convert data to integer
        try:
            brand = int(brand)
        except TypeError:
            flash('invalid category type', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)
        try:
            price = int(price)
        except TabError:
            flash('invalid price type', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)

        # if brand les then 1 send error
        if brand < 1:
            flash('brand not found', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)

        # Save data
        car = create_item(title, description, model, brand, author, price)

        # redirect user
        return redirect('/edit/car/%s' % car.id)

    return render('catalog/new_car.html', brands=brands, csrf=csrf_token)


@app.route('/edit/car/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_car(item_id):
    """
    Edit item

    :param item_id:
    :return mix:
    """

    # get user
    user = get_user_by_id(session['uid'])

    # Get car
    car = get_item_by_id(item_id)

    # Check the user is the owner
    if int(session['uid']) != int(car.author):
        flash('You don\'t have permission to edit it.', 'error')
        return redirect('/profile', 302)

    # Get token
    token = user.generate_auth_token(3600)

    if request.method == 'POST' and request.form['csrf_token'] == csrf_token:
        _car = dict()

        # cleaning data
        try:
            _car['description'] = clean(request.form['description'])
            _car['title'] = clean(request.form['title'])
            _car['model'] = clean(request.form['model'])
            _car['price'] = clean(request.form['price'])
            _car['brand'] = clean(request.form['brand'])
            _car['author'] = session['uid']
        except TypeError:
            flash('fields can\'t be empty', 'error')
            return render('catalog/new_car.html',
                          brands=brands, csrf=csrf_token)

        # update car, create success message and redirect user
        item = update_item(_car, item_id)
        flash('Record "%s" was successfully updated' % item.title, 'success')
        return redirect('/profile', 302)

    return render('catalog/edit_car.html',
                  brands=brands,
                  car=car.serialize,
                  token=token,
                  user=user.serialize,
                  csrf_token=csrf_token)


@app.route('/delete/car/<int:item_id>', methods=['GET', 'POST'])
@login_required
def delete_car(item_id):
    """
    Remove car and all images

    :param item_id:
    :return:
    """

    # Get car
    car = get_item_by_id(item_id)

    # check if the user is the owner
    if int(car.author) != int(session['uid']):
        # crate a error message and redirect user
        flash('You don\'t have permission to remove this object', 'error')
        return redirect('/profile', 302)

    if request.method == 'POST':

        # get images
        images = get_images_by_item_id(item_id)

        # get title
        title = car.title

        # remove images files
        for image in images:
            # get absolute path to image
            path = ''.join([BASE_DIR, image.url])
            # if file exist remove the image file
            if os.path.isfile(path):
                os.unlink(path)

        # remove images from from database
        remove_images_by_item_id(item_id)

        # remove data of car from database
        delete_item(item_id)

        # crate a success message and redirect user
        flash('Car: "%s" was removed' % title, 'success')
        return redirect('/profile', 302)

    return render('catalog/delete_car.html',
                  brands=brands, car=car.serialize, csrf_token=csrf_token)


# TODO: Sign in with provider
@app.route('/api/oauth/<provider>', methods=['POST'])
def oauth(provider):
    """
    Authentication with providers

    :param provider:
    :return:
    """

    # STEP 1 - Parse the auth code
    code = request.data

    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                settings.BASE_DIR + '/client_secrets.json',
                scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token

        # prepare url
        turl = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        url = (turl % access_token)

        # get result
        h = Http()
        result = loads(h.request(url, 'GET')[1])

        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # Get user info
        h = Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        google_response = r_get(userinfo_url, params=params)

        data = google_response.json()

        # see if user exists, if it doesn't make a new one
        user = get_user_by_email(email=data['email'])
        if not user:
            user = create_user(username=data.get('name'),
                               picture=data.get('picture'),
                               email=data.get('email'),
                               first_name=data.get('given_name'),
                               last_name=data.get('family_name'),
                               password=get_unique_str(8))

        g.user = user

        # create session
        session['uid'] = user.id
        session['provider'] = 'google'

        return jsonify({'message': 'Success'}), 200

    elif provider == 'facebook':

        # get data
        data = request.json.get('data')

        # get access token
        access_token = data['access_token']

        # prepare path to app facebook data
        fb_file = ''.join([BASE_DIR, '/facebook.json'])

        # load data
        fb_data = loads(open(fb_file, 'r').read())['facebook']

        # gat app data
        app_id = fb_data['app_id']
        app_secret = fb_data['app_secret']

        # prepare query url for access token
        url = fb_data['access_token_url'] % (app_id, app_secret, access_token)

        # get result
        h = Http()
        result = h.request(url, 'GET')[1]

        # Use token to get user info from API
        token = result.split(',')[0].split(':')[1].replace('"', '')

        # prepare url for get user info
        url = fb_data['user_info_url'] % token

        # get result
        h = Http()
        result = h.request(url, 'GET')[1]

        # load data
        data = loads(result)

        # get first name and last name
        name = findall(r'[a-zA-Z]+', data['name'])

        # prepare dictionary for save
        user_data = dict()
        user_data['provider'] = 'facebook'
        user_data['username'] = ''.join(name)
        user_data['first_name'] = name[0]
        user_data['last_name'] = name[1]
        user_data['email'] = data.get('email')
        user_data['facebook_id'] = data.get('id')
        user_data['access_token'] = token

        # prepare url for get picture
        url = fb_data['picture_url'] % token

        # get result
        h = Http()
        result = h.request(url, 'GET')[1]

        # load data
        data = loads(result)

        # add picture link to dictionary
        user_data['picture'] = data['data']['url']

        # get user info
        user_info = get_user_by_email(user_data['email'])

        # check the user exist, if not create a new one
        if user_info is None:
            user_info = create_user(username=user_data['username'],
                                    password=get_unique_str(8),
                                    first_name=user_data['first_name'],
                                    last_name=user_data['last_name'],
                                    email=user_data['email'],
                                    picture=user_data['picture'])
        g.user = user_info

        # create session
        session['uid'] = user_info.id
        session['provider'] = 'facebook'
        return jsonify({'message': 'Success'}), 200

    else:
        return jsonify({'error': 'Unknown provider'})


@app.route('/logout')
def logout():
    """
    Logout user

    :return:
    """
    if session.get('uid') is not None:
        del session['uid']
    if session.get('provider') is not None:
        del session['provider']

    return redirect('/', 302)


# TODO: All items
@app.route('/api/')
def all_items():
    """
    Return 9 last added items

    :return string: JSON
    """
    items = get_items(limit=9)
    json = [item.serialize for item in items]
    return jsonify(json)


# TODO: Get categories
@app.route('/api/categories')
def categories():
    """
    Return list of categories

    :return string: JSON
    """
    cats = [item.serialize for item in get_categories()]
    return jsonify(cats), 200


# TODO: Get items by category
@app.route('/api/category/<int:category_id>')
def category(category_id):
    """
    Return items by category id

    :param category_id:
    :return string: JSON
    """
    items = [item.serialize for item in get_items_by_category(category_id, 9)]
    return jsonify(items), 200


# TODO: Add new category
@app.route('/api/category/new', methods=['POST'])
@auth.login_required
def add_category():
    """
    Add a new category

    :return string: JSON
    """

    # check user status
    if g.user.status != 'admin':
        return jsonify({'error': "You do not have permission to do that"}), 200

    # get and clean data
    new_category = clean(request.json.get('name'))

    # check category exist
    if check_category(new_category):
        create_category(new_category)

    # return list of categories
    cats = [item.serialize for item in get_categories()]
    return jsonify(cats), 200


# TODO: Get auth token
@app.route('/api/token')
@auth.login_required
def get_auth_token():
    """
    Return auth token

    :return string: JSON
    """
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii'),
                    'uid': g.user.id,
                    'picture': g.user.picture,
                    'username': g.user.username,
                    'first_name': g.user.first_name,
                    'last_name': g.user.last_name,
                    'status': g.user.status,
                    'email': g.user.email,
                    'full_name': g.user.get_full_name})


# TODO: Create a new user
@app.route('/api/users/create', methods=['POST'])
def new_user():
    """
    Create a new user

    :return string: JSON
    """

    # Get user data
    data = request.json.get('data')
    username = clean(data.get('username'))
    password = clean(data.get('password'))
    first_name = clean(data.get('first_name'))
    last_name = clean(data.get('last_name'))
    email = clean(data.get('email'))

    # Check user data
    if len(username) < 3:
        return jsonify({'error': 'username too short'}), 200
    if len(password) < 8:
        return jsonify({'error': 'password must to be more 8 characters'})
    if len(first_name) < 2:
        return jsonify({'error': 'first name is too short, min 2 characters'})
    if len(last_name) < 2:
        return jsonify({'error': 'last name is too short, min 2 characters'})
    if email_is_valid(email) is False:
        return jsonify({'error': 'email is not valid'}), 200

    # Check user exist
    if user_exist(username):
        return jsonify({'error': 'user already exists'}), 200

    # Create a new user
    user = create_user(username, password, first_name, last_name,
                       email) or None
    if user is None:
        return jsonify({'error': 'error create user'}), 200
    g.user = user

    # Data preparation
    data = {'message': 'User created',
            'id': g.user.id,
            'full_name': g.user.get_full_name}
    return jsonify(data), 201


# TODO: Get a profile info by uid
@app.route('/api/profile/<int:uid>')
def show_profile(uid):
    """
    Return serializable users data

    :param uid:
    :return String: (JSON)
    """
    user = get_user_by_id(uid)
    return jsonify(user.serialize)


@app.route('/api/profile/items')
@auth.login_required
def get_user_items():
    """
    Return items by user id

    :return string: JSON
    """
    items = [item.serialize for item in get_items_by_user(int(g.user.id))]
    return jsonify(items), 200


@app.route('/api/car/<int:car_id>')
def get_user_item(car_id):
    """
    Return items by user id

    :return string: JSON
    """
    car = get_item_by_id(car_id)
    return jsonify(car.serialize), 200


# TODO: Edit user photo
@app.route('/api/profile/edit/photo/<int:uid>', methods=['POST'])
def edit_photo(uid):
    """
    Update user's photo (avatar)

    :param uid:
    :return string: JSON
    """

    # check the user is the owner
    user_prof = get_user_by_id(uid)
    if user_prof.id != session['uid']:
        return jsonify({'error': 'permission denied'}), 403

    # check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'error': "Server don't get image"}), 206
    photo = request.files['file']

    # if user does not select file, browser also
    # submit a empty part without filename
    if photo.filename == '':
        return jsonify({'error': 'No selected file'}), 200
    if photo and allowed_file(photo.filename, ALLOWED_EXTENSIONS):
        # prepare relative path to the image for database
        filename = get_path(filename=secure_filename(photo.filename),
                            folder=app.config['UPLOAD_FOLDER'])

        # prepare absolute path to the image for saving
        abs_path = '%s%s' % (BASE_DIR, filename)

        # save image
        photo.save(abs_path)

        # update user data
        user = update_user_photo(filename, user_prof.id)

        return jsonify(user.serialize), 200
    else:
        return jsonify({'error', "Can't update user photo"}), 200


# TODO: Add items photos
@app.route('/api/item/add/images/<int:uid>/<int:item_id>', methods=['POST'])
def add_item_images(uid, item_id):
    """
    Save item's images

    :param uid:
    :param item_id:
    :return string: JSON
    """

    images = list()

    # validate numbers
    try:
        uid = int(uid)
        item_id = int(item_id)
    except ValueError or TypeError:
        return jsonify({'error': "wrong address"})

    # get user data
    user_profile = get_user_by_id(uid)

    # check the user is the owner of the account
    if user_profile.id != session['uid']:
        return jsonify({'error': 'permission denied'}), 403

    # get list of images
    upload_images = request.files.getlist('file')

    # validate images
    if upload_images is []:
        return jsonify({'error': "server didn't get any images"}), 206
    if len(upload_images) > 10:
        return jsonify({'error': "too many images, maximum 10"}), 206

    # prepare data for saving
    for image in upload_images:
        filename = get_path(filename=secure_filename(image.filename),
                            folder=app.config['UPLOAD_FOLDER'])
        abs_path = '%s%s' % (BASE_DIR, filename)
        image.save(abs_path)
        images.append(filename)

    # prepare response
    item_images = [item.serialize for item in add_images(images, item_id)]
    return jsonify(item_images), 200


# TODO: Edit user data
@app.route('/api/profile/edit/<int:uid>', methods=['POST'])
@auth.login_required
def edit_profile(uid):
    """
    Edit user's data

    :param uid:
    :return string: JSON
    """
    # check if the user is the owner
    user_profile = get_user_by_id(uid)
    if user_profile.id != g.user.id:
        return jsonify({'error': 'permission denied'}), 403

    # define user object
    user = {
        'uid': uid,
        'username': clean(request.json.get('username')),
        'first_name': clean(request.json.get('first_name')),
        'last_name': clean(request.json.get('last_name')),
        'email': clean(request.json.get('email')),
    }

    # validate data
    if not user['username']:
        return jsonify({'error': 'username can\'t be empty'})
    if not user['first_name']:
        return jsonify({'error': 'first name can\'t be empty'})
    if not user['last_name']:
        return jsonify({'error': 'last name can\'t be empty'})
    if not user['email']:
        return jsonify({'error': 'email can\'t be empty'})

    if user_profile.email != user['email'] and email_exist(user['email']):
        return jsonify({'error': 'email already registered'})

    # update user
    update_user(user)
    g.user = get_user_by_id(uid)
    return jsonify({'message': 'User %s was update!' % g.user.get_full_name})


# TODO: Delete an user
@app.route('/api/profile/delete/<int:uid>', methods=['POST'])
@auth.login_required
def delete_user(uid):
    """
    Remove user's profile

    :param uid:
    :return string: JSON
    """
    user_info = get_user_by_id(uid)
    if user_info.id != g.user.id:
        return jsonify({'error': 'permission denied'}), 403
    else:
        remove_user(uid)
        return jsonify({'message': 'account was removed'}), 200


# TODO: Create a new item
@app.route('/api/create/item', methods=['POST'])
@auth.login_required
def new_item():
    """
    Create a new item

    :return string: JSON
    """

    # Get and clean data
    title = clean(request.json.get('title'))
    model = clean(request.json.get('model'))
    description = clean(request.json.get('description'))
    brand = request.json.get('brand')
    price = request.json.get('price')
    author = g.user.id

    # Check data
    if len(title) < 5:
        return jsonify({'error': 'too short title, minimum 5 characters'}), 206
    if len(model) < 2:
        return jsonify({'error': 'too short model, minimum 2 characters'}), 206
    if len(description) < 5:
        return jsonify({'error': 'too short description, min 5 symbols'}), 206

    # convert data to integer
    try:
        brand = int(brand)
    except TypeError:
        return jsonify({'error': 'invalid category type'}), 206
    try:
        price = int(price)
    except TabError:
        return jsonify({'error': 'invalid price type'}), 206

    # if brand les then 1 send error
    if brand < 1:
        return jsonify({'error': 'brand not found'}), 206

    # Save data
    item = create_item(title, description, model, brand, author, price)
    return jsonify(item.serialize), 200


@app.route('/api/update/item/<int:item_id>', methods=['POST'])
@auth.login_required
def edit_item(item_id):
    """
    Edit item by id

    :param item_id:
    :return string: JSON
    """

    # get item data
    _item = dict()
    _item['title'] = clean(request.json.get('title'))
    _item['model'] = clean(request.json.get('model'))
    _item['description'] = clean(request.json.get('description'))
    _item['brand'] = request.json.get('brand')
    _item['price'] = request.json.get('price')
    _item['author'] = int(g.user.id)

    # get item
    item = get_item_by_id(item_id) or None

    # check item exist
    if not item:
        return jsonify({'error': 'This record don\'t exist'})

    # check the user is the owner
    if int(item.author) != _item['author']:
        return jsonify(
            {'error': 'You don\'t have permission to edit the record'})

    # Check data
    if len(_item['title']) < 5:
        return jsonify({'error': 'too short title, minimum 5 characters'}), 206
    if len(_item['model']) < 2:
        return jsonify({'error': 'too short model, minimum 2 characters'}), 206
    if len(_item['description']) < 5:
        return jsonify({'error': 'too short description, min 5 symbols'}), 206

    # convert data to integer
    try:
        _item['brand'] = int(_item['brand']['id'])
    except TypeError:
        return jsonify({'error': 'invalid brand type'}), 206
    try:
        _item['price'] = int(_item['price'])
    except TabError:
        return jsonify({'error': 'invalid price type'}), 206

    # update item and send response
    item = update_item(_item, item_id)
    return jsonify(item.serialize), 200


@app.route('/api/delete/item/<int:item_id>', methods=['POST'])
@auth.login_required
def remove_item(item_id):
    """
    Remove item from data base

    :param item_id:
    :return string: JSON
    """
    item = get_item_by_id(item_id) or None

    # check the item exist
    if not item:
        return jsonify({'error': 'This record don\'t exist'})

    # check the user is the owner
    if int(item.author) != int(g.user.id):
        return jsonify(
            {'error': 'You don\'t have permission to delete this record'})

    images = get_images_by_item_id(item_id)

    # remove images files
    for image in images:
        path = ''.join([BASE_DIR, image.url])

        if os.path.isfile(path):
            os.unlink(path)

    # remove item and images from database
    delete_item(item_id)
    remove_images_by_item_id(item_id)
    return jsonify({'message': 'Record was deleted'})


@app.route('/api/item/<int:item_id>')
def item_page(item_id):
    """
    Return item

    :param item_id:
    :return string: JSON
    """
    item = get_item_by_id(item_id)
    return jsonify(item.serialize), 200


if __name__ == '__main__':
    app.secret_key = get_unique_str(32)
    app.debug = True
    app.run(host='0.0.0.0')
