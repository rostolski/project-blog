import hmac
def secure_val(val):
    secret = 'To Infinity and Beyond'
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
