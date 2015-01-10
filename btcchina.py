#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Original code from https://github.com/BTCChina/btcchina-api-python
# Reworked by @pstch
#
# TODO:
#  - Tests (doctests)
#  - Docstrings
#  - More comments and documentation
#  - Check if 'requests' isn't more adapted for this task
#  - Test !
"""BTCChina client"""
from time import time
from re import sub
from hmac import new as new_hmac
from hashlib import sha1
from base64 import b64encode
from httplib import HTTPSConnection
from json import dumps, loads

# The order of params is critical for calculating a correct hash
FIELDS = [
    'tonce', 'accesskey',
    'requestmethod', 'id',
    'method', 'params'
]


class ServerError(Exception):
    """Raised when BTCChina has an error communicating with the remote API
    (either getting the response or parsing it)

    """
    def __init__(self, status_code, reason):
        # `super().__init__` is the `Exception` constructor
        super().__init__(
            "Got unexpected status code {} (reason: {})"
            "".format(status_code, reason)
        )


class BTCChina:
    _conn = None
    access_key = None
    secret_key = None
    hostname = "api.btcchina.com"
    path = "/api_trade_v1.php"

    @property
    def connection(self):
        """Get connection, ensure that it is not used when not open."""
        if self._conn is not None:
            return self._conn
        else:
            raise RuntimeError(
                "Cannot use connection when no connection made"
            )

    @connection.setter
    def connection(self, value):
        """Set connection"""
        self._conn = value

    def __init__(self, access_key=None, secret_key=None,
                 hostname=None, path=None, no_enter=False):
        """BTC China client constructor

        By default, opens the HTTPS connection (unless
        :attr:`no_enter` is given) by opening the context manager
        (calling :func:`__enter__`)

        :argument access_key: API access key
        :type access_key: str
        :argument secret_key: API secret key
        :type secret_key: str
        :argument hostname: Remote hostname
        :type hostname: str
        :argument path: Path
        :type path: str
        :argument no_enter: Disable
        :type path: str
        """
        if access_key is not None:
            self.access_key = access_key
        elif self.access_key is None:
            raise RuntimeError(
                "No access key given (set it as class attribute "
                "or give it in constructor)"
            )
        if secret_key is not None:
            self.secret_key = secret_key
        elif self.secret_key is None:
            raise RuntimeError(
                "No secret key given (set it as class attribute "
                "or give it in constructor)"
            )
        if hostname is not None:
            self.hostname = hostname
        elif self.hostname is None:
            raise RuntimeError(
                "No hostname given (set it as class attribute or "
                "give it in constructor)"
            )
        if path is not None:
            self.path = path
        elif self.path is None:
            raise RuntimeError(
                "No path given (set it as class attribute or "
                "give it in constructor)"
            )

        if not no_enter:
            # make connection
            self.__enter__()

    def _make_connection(self):
        """Open connection"""
        return HTTPSConnection(self.hostname)

    def _send_request(self, data, headers):
        """Send request"""
        data = dumps(data)
        self.connection.request("POST", self.path, data, headers)

    def _get_response(self):
        """Wait for HTTP response"""
        return self.connection.getresponse()

    def close(self):
        """Close connection"""
        self.connection.close()

    def __enter__(self):
        """Enter context (open connection)"""
        self.connection = self._make_connection()

    def __exit__(self, *exc_details):
        """Exit context (close connection)"""
        self.close()

    def _get_tonce(self):
        """# TODO"""
        return int(time()*1000000)

    def _get_params_hash(self, pdict):
        """# TODO"""
        pstring = ""

        for f in FIELDS:
            if pdict[f]:
                if f == 'params':
                    # Convert list to string, then strip brackets and spaces
                    # probably a cleaner way to do this
                    param_string = sub("[\[\] ]", "", str(pdict[f]))
                    param_string = sub("'", '', param_string)
                    param_string = sub("True", '1', param_string)
                    param_string = sub("False", '', param_string)
                    param_string = sub("None", '', param_string)
                    pstring += '{}={}&'.format(f, param_string)
                else:
                    pstring += '{}={}&'.format(f, str(pdict[f]))
            else:
                pstring += '{}=&'.format(f)

        pstring = pstring.strip('&')

        # now with correctly ordered param string, calculate hash
        return new_hmac(self.secret_key, pstring, sha1).hexdigest()

    def _private_request(self, post_data):
        """# TODO"""
        # fill in common post_data parameters
        tonce = self._get_tonce()
        post_data['tonce'] = tonce
        post_data['accesskey'] = self.access_key
        post_data['requestmethod'] = 'post'

        # If ID is not passed as a key of post_data, just use tonce
        if 'id' not in post_data:
            post_data['id'] = tonce

        pd_hash = self._get_params_hash(post_data)

        # must use b64 encode
        auth_string = 'Basic ' + b64encode(
            ':'.join([self.access_key, pd_hash])
        )
        headers = {'Authorization': auth_string, 'Json-Rpc-Tonce': tonce}

        # post_data dictionary passed as JSON
        self._send_request(post_data, headers)
        response = self._get_response()
        status_code = response.status

        # check response code, ID, and existence of 'result' or 'error'
        # before passing a dict of results
        if status_code == 200:
            # this might fail if non-json data is returned
            resp_dict = loads(response.read())

            # The id's may need to be used by the calling application,
            # but for now, check and discard from the return dict
            if str(resp_dict['id']) == str(post_data['id']):
                if 'result' in resp_dict:
                    return resp_dict['result']
                elif 'error' in resp_dict:
                    return resp_dict['error']
                else:
                    reason = "No 'result' or 'error' items found in response"
            else:
                reason = "IDs do not match in response and request"

        raise ServerError(
            status_code, reason
        )

    def get_account_info(self, post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        post_data['method'] = 'getAccountInfo'
        post_data['params'] = ()

        return self._private_request(post_data)

    def get_market_depth2(self, limit=10, market="btccny", post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        post_data['method'] = 'getMarketDepth2'
        post_data['params'] = limit, market

        return self._private_request(post_data)

    def buy(self, price, amount, market="btccny", post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        amount_str = "{0:.4f}".format(round(amount, 4))
        post_data['method'] = 'buyOrder2'

        if price is None:
            price_str = None
        else:
            price_str = "{0:.4f}".format(round(price, 4))

        post_data['params'] = price_str, amount_str, market

        return self._private_request(post_data)

    def sell(self, price, amount, market="btccny", post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        amount_str = "{0:.4f}".format(round(amount, 4))

        post_data['method'] = 'sellOrder2'

        if price is None:
            price_str = None
        else:
            price_str = "{0:.4f}".format(round(price, 4))

        post_data['params'] = price_str, amount_str, market

        return self._private_request(post_data)

    def cancel(self, order_id, market="btccny", post_data=None):
        if post_data is None:
            post_data = {}

        post_data['method'] = 'cancelOrder'
        post_data['params'] = order_id, market

        return self._private_request(post_data)

    def request_withdrawal(self, currency, amount, post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        post_data['method'] = 'requestWithdrawal'
        post_data['params'] = currency, amount

        return self._private_request(post_data)

    def get_deposits(self, currency='BTC', pending=True, post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        post_data['method'] = 'getDeposits'
        post_data['params'] = currency, pending

        return self._private_request(post_data)

    def get_orders(self, id=None, open_only=True, market="btccny",
                   details=True, post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        # this combines getOrder and getOrders
        if id is None:
            post_data['method'] = 'getOrders'
            post_data['params'] = open_only, market
        else:
            post_data['method'] = 'getOrder'
            post_data['params'] = id, market, details

        return self._private_request(post_data)

    def get_withdrawals(self, id='BTC', pending=True, post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        # this combines getWithdrawal and getWithdrawals
        try:
            id = int(id)
            post_data['method'] = 'getWithdrawal'
            post_data['params'] = id,
        except:
            post_data['method'] = 'getWithdrawals'
            post_data['params'] = id, pending

        return self._private_request(post_data)

    def get_transactions(self, trans_type='all', limit=10, post_data=None):
        """# TODO"""
        if post_data is None:
            post_data = {}

        post_data['method'] = 'getTransactions'
        post_data['params'] = trans_type, limit

        return self._private_request(post_data)
