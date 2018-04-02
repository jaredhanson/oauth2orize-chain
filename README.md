# oauth2orize-chain

Chained token exchange for [OAuth2orize](https://github.com/jaredhanson/oauth2orize).

This exchange is used by a protected service to exchange a token it receives
from a client for a token it can use to access another protected service,
potentially within a different security domain.  This scenario facilitiates
service chaining, in which one service needs to communicate with another service
in order to fulfill the original request.

Status:
[![Version](https://img.shields.io/npm/v/oauth2orize-chain.svg?label=version)](https://www.npmjs.com/package/oauth2orize-chain)
[![Build](https://img.shields.io/travis/jaredhanson/oauth2orize-chain.svg)](https://travis-ci.org/jaredhanson/oauth2orize-chain)
[![Quality](https://img.shields.io/codeclimate/github/jaredhanson/oauth2orize-chain.svg?label=quality)](https://codeclimate.com/github/jaredhanson/oauth2orize-chain)
[![Coverage](https://img.shields.io/coveralls/jaredhanson/oauth2orize-chain.svg)](https://coveralls.io/r/jaredhanson/oauth2orize-chain)
[![Dependencies](https://img.shields.io/david/jaredhanson/oauth2orize-chain.svg)](https://david-dm.org/jaredhanson/oauth2orize-chain)


## Install

```bash
$ npm install oauth2orize-chain
```

## Usage

#### Register Exchange

Register the exchange with a `Server` instance and implement the `issue`
callback:

```js
var chain = require('oauth2orize-chain').exchange.chain;

server.exchange('http://oauth.net/grant_type/chain', chain(function(client, token, scope, done) {
  // TODO:
  // 1. Verify the access token.
  // 2. Ensure that the token is being exchanged by a resource server for which
  //    it is intended.
  // 3. Issue a chained access token.
});
```

## Considerations

#### Specification

This module is implemented based on [Chain Grant Type for OAuth2](http://tools.ietf.org/html/draft-hunt-oauth-chain-01),
draft version 01.  As a draft, the specification remains a work-in-progress and
is *not* final.  The specification is under discussion within the [OAuth Working Group](https://datatracker.ietf.org/wg/oauth/about/)
of the [IETF](https://www.ietf.org/).  Implementers are encouraged to track the
progress of this specification and update implementations as necessary.
Furthermore, the implications of relying on non-final specifications should be
understood prior to deployment.

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2014-2018 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
