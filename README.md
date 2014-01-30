# oauth2orize-chain

[![Build](https://travis-ci.org/jaredhanson/oauth2orize-chain.png)](https://travis-ci.org/jaredhanson/oauth2orize-chain)
[![Coverage](https://coveralls.io/repos/jaredhanson/oauth2orize-chain/badge.png)](https://coveralls.io/r/jaredhanson/oauth2orize-chain)
[![Quality](https://codeclimate.com/github/jaredhanson/oauth2orize-chain.png)](https://codeclimate.com/github/jaredhanson/oauth2orize-chain)
[![Dependencies](https://david-dm.org/jaredhanson/oauth2orize-chain.png)](https://david-dm.org/jaredhanson/oauth2orize-chain)
[![Tips](http://img.shields.io/gittip/jaredhanson.png)](https://www.gittip.com/jaredhanson/)


Chained token exchange for [OAuth2orize](https://github.com/jaredhanson/oauth2orize).

This exchange is used to exchange an access token issued by an OAuth domain for
a chained access token, potentially issued by a different OAuth domain.  This
scenario facilitiates service chaining, in which one service needs to
communicate with another service in order to fulfill the original request.

## Install

    $ npm install oauth2orize-chain

## Usage

#### Register Exchange

Register the exchange with an OAuth 2.0 server.

```javascript
var chain = require('oauth2orize-chain').exchange.chain;

server.exchange('http://oauth.net/grant_type/chain', chain(function(client, scheme, credential, scope, done) {
  AccessToken.verify(credential, function(err, t) {
    if (err) { return done(err); }

    var token = utils.uid(256);
    var at = new AccessToken(token, t.userId, client.id, t.scope);
    at.save(function(err) {
      if (err) { return done(err); }
      return done(null, token);
    });
  });
});
```

## Implementation

This module is implemented based on [Chain Grant Type for OAuth2](http://tools.ietf.org/html/draft-hunt-oauth-chain-01),
Draft 01.  Implementers are encouraged to track the progress of this
specification and update update their implementations as necessary.
Furthermore, the implications of relying on a non-final draft specification
should be understood prior to deployment.

## Related Modules

- [oauth2orize-redelegate](https://github.com/jaredhanson/oauth2orize-redelegate) — token redelegation exchange

## Tests

    $ npm install
    $ npm test

## Credits

  - [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2014 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
