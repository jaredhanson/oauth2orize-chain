/* global describe, it, expect, before */

var chai = require('chai')
  , chain = require('../../lib/exchange/chain');


describe('exchange.chain', function() {
  
  it('should be named chain', function() {
    expect(chain(function(){}).name).to.equal('chain');
  });
  
  it('should throw if constructed without an issue callback', function() {
    expect(function() {
      chain();
    }).to.throw(TypeError, 'oauth2orize-chain exchange requires an issue callback');
  });
  
  describe('issuing an access token', function() {
    var response;

    before(function(done) {
      function issue(client, token, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        
        return done(null, 's3cr1t');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
  describe('issuing an access token and refresh token', function() {
    var response;

    before(function(done) {
      function issue(client, token, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        
        return done(null, 's3cr1t', 'getANotehr');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","refresh_token":"getANotehr","token_type":"Bearer"}');
    });
  });
  
  describe('issuing an access token and params', function() {
    var response;

    before(function(done) {
      function issue(client, token, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        
        return done(null, 's3cr1t', { 'expires_in': 3600 });
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","expires_in":3600,"token_type":"Bearer"}');
    });
  });
  
  describe('issuing an access token and params with token type', function() {
    var response;

    before(function(done) {
      function issue(client, token, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        
        return done(null, 's3cr1t', { 'token_type': 'foo', 'expires_in': 3600 });
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"foo","expires_in":3600}');
    });
  });
  
  describe('issuing an access token, null refresh token, and params', function() {
    var response;

    before(function(done) {
      function issue(client, token, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        
        return done(null, 's3cr1t', null, { 'expires_in': 3600 });
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","expires_in":3600,"token_type":"Bearer"}');
    });
  });
  
  describe('issuing an access token, refresh token, and params with token type', function() {
    var response;

    before(function(done) {
      function issue(client, token, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        
        return done(null, 's3cr1t', 'blahblag', { 'token_type': 'foo', 'expires_in': 3600 });
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","refresh_token":"blahblag","token_type":"foo","expires_in":3600}');
    });
  });
  
  describe('issuing an access token based on scope', function() {
    var response;

    before(function(done) {
      function issue(client, token, scope, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        if (scope.length !== 1 || scope[0] !== 'read') { return done(new Error('incorrect scope argument')); }
        
        return done(null, 's3cr1t');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh', scope: 'read' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
  describe('issuing an access token based on list of scopes', function() {
    var response;

    before(function(done) {
      function issue(client, token, scope, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        if (scope.length !== 2 || scope[0] !== 'read' || scope[1] !== 'write') { return done(new Error('incorrect scope argument')); }
        
        return done(null, 's3cr1t');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh', scope: 'read write' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
  describe('issuing an access token based on scheme and scope', function() {
    var response;

    before(function(done) {
      function issue(client, token, scheme, scope, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        if (scheme !== 'Bearer') { return done(new Error('incorrect scheme argument')); }
        if (scope.length !== 1 || scope[0] !== 'read') { return done(new Error('incorrect scope argument')); }
        
        return done(null, 's3cr1t');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh', scope: 'read' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
  describe('issuing an access token based on scheme, scope, body and authInfo', function() {
    var response;

    before(function(done) {
      function issue(client, token, scheme, scope, body, authInfo, done) {
        if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
        if (token !== 'shh') { return done(new Error('incorrect token argument')); }
        if (scheme !== 'Bearer') { return done(new Error('incorrect scheme argument')); }
        if (scope.length !== 1 || scope[0] !== 'read') { return done(new Error('incorrect scope argument')); }
        if (body.foo !== 'bar') { return done(new Error('incorrect body argument')); }
        if (authInfo.ip !== '127.0.0.1') { return done(new Error('incorrect authInfo argument')); }
        
        return done(null, 's3cr1t');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh', scope: 'read', foo: 'bar' };
          req.authInfo = { ip: '127.0.0.1' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
  describe('not issuing an access token', function() {
    var err;

    before(function(done) {
      function issue(client, token, done) {
        return done(null, false);
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Invalid OAuth token');
      expect(err.code).to.equal('invalid_grant');
      expect(err.status).to.equal(403);
    });
  });
  
  describe('handling a request in which the body has not been parsed', function() {
    var err;

    before(function(done) {
      function issue(client, token, done) {
        return done(null, '.ignore');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?');
    });
  });
  
  describe('handling a request without oauth_token parameter', function() {
    var err;

    before(function(done) {
      function issue(client, token, done) {
        return done(null, '.ignore');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = {};
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Missing required parameter: oauth_token');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });
  
  describe('handling a request with malformed oauth_token parameter', function() {
    var err;

    before(function(done) {
      function issue(client, token, done) {
        return done(null, '.ignore');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'shh' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal('Malformed parameter: oauth_token');
      expect(err.code).to.equal('invalid_request');
      expect(err.status).to.equal(400);
    });
  });
  
  describe('encountering an error while issuing an access token', function() {
    var err;

    before(function(done) {
      function issue(client, token, done) {
        return done(new Error('something went wrong'));
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went wrong');
    });
  });
  
  describe('encountering an exception while issuing an access token', function() {
    var err;

    before(function(done) {
      function issue(client, token, done) {
        throw new Error('something went horribly wrong');
      }
      
      chai.connect.use(chain(issue))
        .req(function(req) {
          req.user = { id: 'c123' };
          req.body = { oauth_token: 'Bearer shh' };
        })
        .next(function(e) {
          err = e;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err.message).to.equal('something went horribly wrong');
    });
  });
  
  describe('options', function() {
    
    describe('userProperty', function() {
      
      describe('issuing an access token', function() {
        var response;

        before(function(done) {
          function issue(client, token, done) {
            if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
            if (token !== 'shh') { return done(new Error('incorrect token argument')); }
            
            return done(null, 's3cr1t');
          }
      
          chai.connect.use(chain({ userProperty: 'client' }, issue))
            .req(function(req) {
              req.client = { id: 'c123' };
              req.body = { oauth_token: 'Bearer shh' };
            })
            .end(function(res) {
              response = res;
              done();
            })
            .dispatch();
        });
    
        it('should respond with headers', function() {
          expect(response.getHeader('Content-Type')).to.equal('application/json');
          expect(response.getHeader('Cache-Control')).to.equal('no-store');
          expect(response.getHeader('Pragma')).to.equal('no-cache');
        });
    
        it('should respond with body', function() {
          expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
        });
      });
      
    }); // userProperty
    
    describe('scopeSeparator', function() {
      
      describe('single separator', function() {
        var response;

        before(function(done) {
          function issue(client, token, scope, done) {
            if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
            if (token !== 'shh') { return done(new Error('incorrect token argument')); }
            if (scope.length !== 2 || scope[0] !== 'read' || scope[1] !== 'write') { return done(new Error('incorrect scope argument')); }
            
            return done(null, 's3cr1t');
          }
      
          chai.connect.use(chain({ scopeSeparator: ',' }, issue))
            .req(function(req) {
              req.user = { id: 'c123' };
              req.body = { oauth_token: 'Bearer shh', scope: 'read,write' };
            })
            .end(function(res) {
              response = res;
              done();
            })
            .dispatch();
        });
    
        it('should respond with headers', function() {
          expect(response.getHeader('Content-Type')).to.equal('application/json');
          expect(response.getHeader('Cache-Control')).to.equal('no-store');
          expect(response.getHeader('Pragma')).to.equal('no-cache');
        });
    
        it('should respond with body', function() {
          expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
        });
      }); // single separator
      
      describe('multiple separators', function() {
        
        describe('separating based on preferred separator', function() {
          var response;

          before(function(done) {
            function issue(client, token, scope, done) {
              if (client.id !== 'c123') { return done(new Error('incorrect client argument')); }
              if (token !== 'shh') { return done(new Error('incorrect token argument')); }
              if (scope.length !== 2 || scope[0] !== 'read' || scope[1] !== 'write') { return done(new Error('incorrect scope argument')); }
            
              return done(null, 's3cr1t');
            }
      
            chai.connect.use(chain({ scopeSeparator: [' ', ','] }, issue))
              .req(function(req) {
                req.user = { id: 'c123' };
                req.body = { oauth_token: 'Bearer shh', scope: 'read write' };
              })
              .end(function(res) {
                response = res;
                done();
              })
              .dispatch();
          });
    
          it('should respond with headers', function() {
            expect(response.getHeader('Content-Type')).to.equal('application/json');
            expect(response.getHeader('Cache-Control')).to.equal('no-store');
            expect(response.getHeader('Pragma')).to.equal('no-cache');
          });
    
          it('should respond with body', function() {
            expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
          });
        }); // separating based on preferred separator
        
        describe('separating based on alternate separator', function() {
          var response;

          before(function(done) {
            function issue(client, token, scope, done) {
              if (client.id == 'c123' && token == 'shh' && scope.length == 2 && scope[0] == 'read' && scope[1] == 'write') {
                return done(null, 's3cr1t');
              }
              return done(new Error('something is wrong'));
            }
      
            chai.connect.use(chain({ scopeSeparator: [' ', ','] }, issue))
              .req(function(req) {
                req.user = { id: 'c123' };
                req.body = { oauth_token: 'Bearer shh', scope: 'read,write' };
              })
              .end(function(res) {
                response = res;
                done();
              })
              .dispatch();
          });
    
          it('should respond with headers', function() {
            expect(response.getHeader('Content-Type')).to.equal('application/json');
            expect(response.getHeader('Cache-Control')).to.equal('no-store');
            expect(response.getHeader('Pragma')).to.equal('no-cache');
          });
    
          it('should respond with body', function() {
            expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
          });
        }); // separating based on alternate separator
        
      }); // multiple separators
      
    }); // scopeSeparator
    
  }); // options
  
});
