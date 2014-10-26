# -*- coding: utf-8 -*-

__author__ = 'Takashi Yahata (@paoneJP)'
__copyright__ = 'Copyright (c) 2014, Takashi Yahata'
__license__ = 'MIT License'


import json
import string
from base64 import urlsafe_b64encode, urlsafe_b64decode
from time import time
from uuid import uuid4
from urllib.parse import urlencode, parse_qs

from Crypto.Random import random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.number import bytes_to_long

from bottle import view, request, response
import bottle


REQUEST_DURATION = 300
SESSION_DURATION = 86400


def _str(b):
    return str(b, 'utf-8')


def _bytes(s):
    return bytes(s, 'utf-8')


def base64url_encode(s):
    return _str(urlsafe_b64encode(s)).rstrip('=')


def base64url_decode(s):
    return urlsafe_b64decode(s+'==')


def random_string(n=8):
    chars = string.ascii_letters + string.digits
    rv = ''.join([random.choice(chars) for i in range(n)])
    return rv


app = bottle.app()
get = app.get
post = app.post

request_store = dict()
session_store = dict()


def require_session(callback):
    def wrapper(*args, **kwargs):
        id = request.get_cookie('SESSION')
        session = session_store.get(id)
        if not session or \
               session['timestamp'] + SESSION_DURATION < int(time()):
            bottle.redirect('/authn')
        return callback(session, *args, **kwargs)
    return wrapper


@get('/')
@view('index_get.html')
def index_get():
    pass


@get('/authn')
@view('authn_get.tmpl')
def start_get():
    state = random_string()
    r = request.urlparts
    client_id = '{}://{}/cb'.format(r.scheme, r.netloc)
    request_store[state] = dict(state=state,
                                client_id=client_id,
                                timestamp=int(time()))
    q = urlencode(dict(response_type='id_token',
                       client_id=client_id,
                       scope='openid',
                       state=state))
    url = 'openid://?' + q
    alturl = 'http://localhost:8080/?' + q
    return dict(url=url, alturl=alturl)


@get('/cb')
@view('cb_get.tmpl')
def cb_get():
    return dict(url='/cb')


@post('/cb')
def cb_post():

    def get_value(res, key):
        rv = res.get(key)
        if isinstance(rv, list):
            rv = rv[0]
        return rv

    class IDTokenError(Exception):
        pass

    res = parse_qs(request.forms.get('qs'))

    # validate state
    state = get_value(res, 'state')
    req = request_store.get(state)
    if not req or \
           req['timestamp'] + REQUEST_DURATION < int(time()):
        bottle.abort(400)

    # request state can be used once
    del(request_store[state])

    # authentication response is error
    err = get_value(res, 'error')
    if err:
        bottle.abort(403, (err, get_value(res, 'error_description')))

    # validate id_token
    try:

        # parse id_token
        v = get_value(res, 'id_token')
        if not v:
            raise IDTokenError('id_token not found')

        try:
            (h, p, s) = v.rsplit('.', 2)
        except ValueError:
            raise IDTokenError('JWT format error')

        header = json.loads(_str(base64url_decode(h)))
        payload = json.loads(_str(base64url_decode(p)))
        signature = base64url_decode(s)

        try:

            # validate header
            if not header['typ'] == 'JWT' or not header['alg'] == 'RS256':
                raise IDTokenError('invalid typ or alg')

            # get public key from sub_jwk claim
            jwk = payload.get('sub_jwk', dict())
            n = bytes_to_long(base64url_decode(jwk['n']))
            e = bytes_to_long(base64url_decode(jwk['e']))
            pk = RSA.construct((n, e))

            # validate signature
            hash = SHA256.new(_bytes(h+'.'+p))
            r = PKCS1_v1_5.new(pk).verify(hash, signature)
            if not r:
                raise IDTokenError('invalid signature')

        except KeyError:
            raise IDTokenError('JWT format error')

        # validate iss
        if not payload.get('iss') == 'https://self-issued.me':
            raise IDTokenError('issuer is not Self-Issued OP')

        # validate aud
        if not payload.get('aud') == req['client_id']:
            raise IDTokenError('client_id is not match')

        # validate sub
        v = payload['sub_jwk']['n'] + payload['sub_jwk']['e']
        sub = base64url_encode(SHA256.new(_bytes(v)).digest())
        if not payload.get('sub') == sub:
            raise IDTokenError('invalid sub')

        # validate exp
        exp = payload.get('exp')
        if not exp or not int(time()) < exp:
            raise IDTokenError('id_token is expired')

        # validate nonce
        nonce = req.get('nonce')
        if nonce and not nonce == payload.get('nonce'):
            raise IDTokenError('nonce is not match')

        # fixup
        del(payload['sub_jwk'])

    except IDTokenError as e:
        bottle.abort(403, ('invalid_id_token', e.args[0]))

    # start new session
    id = uuid4().hex
    session_store[id] = dict(id=id, timestamp=int(time()), id_token=payload)
    response.set_cookie('SESSION', id, httponly=True)

    bottle.redirect('/info')


@get('/info')
@view('info_get.tmpl')
@require_session
def info_get(session):
    return dict(id_token=session.get('id_token'))


bottle.run(app=app, port=8081)
