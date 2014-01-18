/* global describe, it, expect */

var chain = require('..');

describe('oauth2orize-chain', function() {
  
  it('should export exchanges', function() {
    expect(chain.exchange).to.be.an('object');
    expect(chain.exchange.chain).to.be.a('function');
  });
  
});
