var chai = require('chai')
  , chain = require('../../lib/exchange/chain');


describe('exchange.chain', function() {
  
  it('should be named chain', function() {
    expect(chain(function(){}).name).to.equal('chain');
  });
  
  it('should throw if constructed without an issue callback', function() {
    expect(function() {
      chain();
    }).to.throw(TypeError, 'chain exchange requires an issue callback');
  });
  
  describe('issuing an access token', function() {
    var response, err;

    before(function(done) {
      function issue(client, token, done) {
        if (client.id == 'c123' && token == 'shh') {
          return done(null, 's3cr1t')
        }
        return done(new Error('something is wrong'));
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
  
});
