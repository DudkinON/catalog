# Carcat - items catalog 

Basis for creating larger projects. This project provides 
main the users functionality to sign in with oauth providers, and manage content.

## Install
1. install  [GIT](https://git-scm.com/downloads).
2. install [Python 2.7.14](https://www.python.org/downloads/release/python-2714/)
2. Enter into terminal the following commands:

```git
git clone https://github.com/DudkinON/catalog
```
```
pip install -r requirements.txt
```
```
cd carcat/items_catalog
```

```
python main.py 
```

> After, it will run flask api and you'll see text like this:

```
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 121-184-468
```

> Go to [http://localhost:5000](http://localhost:5000)

## Config
#### Settings OAuth providers
Carcat support two OAuth providers: Google and FaceBook.

##### Google
In root directory find file **"client_secrets.json"** and edit values: **client_id**, 
**project_id**, **client_secret**, or if you familiar with Google OAuth replace file 
with yours. Don't change file name.

In directory "templates" find file "default.html". In file "default.html" find 
following code:
```html
<meta id="google-app-id"
    data-key-api="YOUR_KEY_API"
    data-clientid="YOUR_CLIENT_ID"
    data-scope="openid email"
    data-redirecturi="postmessage"
    data-accesstype="offline"
    data-cookiepolicy="single_host_origin"
    data-approvalprompt="force">
```
and replace the values with yours data. About each parameter, your can 
familiarizing in [official documentation](https://developers.google.com/api-client-library/).

##### FaceBook
In root directory open file: **"facebook.json"**, and replace values: **app_id** 
and **app_secret** with your data.

In directory **"templates"** find file **"default.html"**. In file 
**"default.html"** find following code:

```html
<meta id="facebook-app-id" data-app-id="YOUR_APP_ID">
```
and replace **YOUR_APP_ID** on yours


> **Note:** Do not rename files: **facebook.json** and **client_secrets.json**.
On file **facebook.json** do not change or delete **access_token_url**, 
**user_info_url** and **picture_url**, app use this data.

> **Important:** In Google api libraries turn on: **Gmail API** and **Google+ API**. 
App use both.


## Demo
Demo you can see it here: [www.carcat.tk](http://www.carcat.tk)

## Used:

* [Python 2.7.14](https://www.python.org/downloads/release/python-2714/)
* Python modules in [requirements.txt](requirements.txt)
* [AngularJS 1.6.6](https://angularjs.org/)

## License

[MIT](LICENSE)